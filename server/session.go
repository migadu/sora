//	[x] Close() error
// Not authenticated state -----
//	[x] Login(username, password string) error
// Authenticated state ---------
//	[x] Select(mailbox string, options *imap.SelectOptions) (*imap.SelectData, error)
// 	[x] Create(mailbox string, options *imap.CreateOptions) error
// 	[x] Delete(mailbox string) error
// 	[x] Rename(mailbox, newName string) error
// 	[x] Subscribe(mailbox string) error
// 	[x] Unsubscribe(mailbox string) error
// 	[x] List(w *ListWriter, ref string, patterns []string, options *imap.ListOptions) error
// 	[x] Status(mailbox string, options *imap.StatusOptions) (*imap.StatusData, error)
// 	[x] Append(mailbox string, r imap.LiteralReader, options *imap.AppendOptions) (*imap.AppendData, error)
// 	Poll(w *UpdateWriter, allowExpunge bool) error
// 	Idle(w *UpdateWriter, stop <-chan struct{}) error

// 	// Selected state
// 	[x] Unselect() error
// 	[x] Expunge(w *ExpungeWriter, uids *imap.UIDSet) error
// 	[x] Search(kind NumKind, criteria *imap.SearchCriteria, options *imap.SearchOptions) (*imap.SearchData, error)
// 	[x] Fetch(w *FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error
// 	[x] Store(w *FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, options *imap.StoreOptions) error
// 	[x] Copy(numSet imap.NumSet, dest string) (*imap.CopyData, error)
// }

// // SessionNamespace is an IMAP session which supports NAMESPACE.
// type SessionNamespace interface {
// 	Session

// 	// Authenticated state
// 	Namespace() (*imap.NamespaceData, error)
// }

// // SessionMove is an IMAP session which supports MOVE.
// type SessionMove interface {
// 	Session

//		// Selected state
//		Move(w *MoveWriter, numSet imap.NumSet, dest string) error
//	}
package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-message"
	_ "github.com/emersion/go-message/charset"
	"github.com/emersion/go-message/mail"
	"github.com/google/uuid"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
)

type SoraSession struct {
	server  *SoraServer
	conn    *imapserver.Conn
	user    *SoraUser
	mailbox *SoraMailbox
}

func (s *SoraSession) Capabilities() []string {
	var caps []string
	for cap := range s.server.caps {
		caps = append(caps, string(cap))
	}
	return caps
}

func (s *SoraSession) Append(mboxName string, r imap.LiteralReader, options *imap.AppendOptions) (*imap.AppendData, error) {
	var result *imap.AppendData
	var err error

	ctx := context.Background()

	pathComponents := strings.Split(mboxName, string(consts.MailboxDelimiter))
	mailbox, err := s.server.db.GetMailboxByFullPath(ctx, s.user.userID, pathComponents)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNonExistent,
				Text: fmt.Sprintf("mailbox '%s' does not exist", mboxName),
			}
		}
		return nil, newInternalServerError("failed to fetch mailbox '%s': %v", mboxName, err)
	}

	// Read the entire message into a buffer
	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	if err != nil {
		return nil, newInternalServerError("failed to read message: %v", err)
	}

	parseReader := bytes.NewReader(buf.Bytes())

	messageContent, err := ParseMessage(parseReader)
	if err != nil {
		return nil, newInternalServerError("failed to parse message: %v", err)
	}

	// Define the append operation that will be retried
	operation := func() error {
		// Create a new copy of the buffer for each attempt
		appendBuf := bytes.NewBuffer(buf.Bytes())
		result, err = s.appendSingle(ctx, mailbox, messageContent, appendBuf, options)
		if err != nil {
			if err == consts.ErrInternalError ||
				err == consts.ErrMalformedMessage {
				return backoff.Permanent(&backoff.PermanentError{Err: err})
			}
			if err == consts.ErrMessageExists {
				log.Printf("Message already exists: %v, ignoring", err)
				return nil
			}
			log.Printf("Append operation failed: %v", err)
			return err
		}
		return nil
	}

	// TODO: Make this configurable
	// Set up exponential backoff
	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.InitialInterval = 500 * time.Millisecond
	expBackoff.MaxInterval = 10 * time.Second
	expBackoff.MaxElapsedTime = 1 * time.Minute

	// Run the operation with retries
	if err := backoff.Retry(operation, expBackoff); err != nil {
		if errors.Is(err, backoff.Permanent(&backoff.PermanentError{Err: err})) {
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeAlreadyExists,
				Text: fmt.Sprintf("message already exists: %v", err),
			}
		}
		// If retries fail, return the last error
		return nil, newInternalServerError("failed to append message: %v", err)
	}

	// Update the last poll time for the mailbox
	s.mailbox.lastPollAt = time.Now()

	// If successful, return the AppendData
	return result, nil
}

// Actual logic for appending a single message to the mailbox
func (s *SoraSession) appendSingle(ctx context.Context, mbox *db.Mailbox, messageContent *message.Entity, buf *bytes.Buffer, options *imap.AppendOptions) (*imap.AppendData, error) {
	bufSize := int64(buf.Len())
	s3UploadBuf := bytes.NewBuffer(buf.Bytes())

	// Parse message headers (this does not consume the body)
	mailHeader := mail.Header{messageContent.Header}
	subject, _ := mailHeader.Subject()
	messageID, _ := mailHeader.MessageID()
	sentDate, _ := mailHeader.Date()
	inReplyTo, _ := mailHeader.MsgIDList("In-Reply-To")

	if sentDate.IsZero() {
		sentDate = options.Time
	}

	bodyStructure, plaintextBody, err := helpers.ExtractBodyStructure(messageContent, buf, true)
	if err != nil {
		log.Printf("Failed to extract body structure: %v", err)
		return nil, consts.ErrMalformedMessage
	}

	// log.Println("Plaintext body:", *plaintextBody)
	recipients := db.ExtractRecipients(messageContent)
	// Generate a new UUID for the message
	uuidKey := uuid.New()

	messageUID, err := s.server.db.InsertMessage(ctx, mbox.ID, uuidKey, messageID, options.Flags, options.Time, bufSize, subject, plaintextBody, sentDate, inReplyTo, s3UploadBuf, &bodyStructure, &recipients, func(uid uuid.UUID, s3Buf *bytes.Buffer, s3BufSize int64) error {
		s3DestKey := S3Key(s.user, uid)
		return s.server.s3.SaveMessage(s3DestKey, s3Buf, s3BufSize)
	})
	if err != nil {
		if err == consts.ErrDBUniqueViolation {
			// Message already exists, continue with the next message
			return nil, consts.ErrMessageExists
		}
		return nil, consts.ErrInternalError
	}

	appendData := &imap.AppendData{
		UID:         imap.UID(messageUID),
		UIDValidity: mbox.UIDValidity,
	}

	return appendData, nil
}

func extractPlaintextBody(msg *message.Entity) (*string, error) {
	for {
		mediaType, _, err := msg.Header.ContentType()
		if err != nil {
			return nil, err
		}
		fmt.Println(mediaType)
		if mediaType == "text/plain" {
			body, err := io.ReadAll(msg.Body)
			if err != nil {
				return nil, err
			}
			plaintext := string(body)
			return &plaintext, nil
		}

		if msg.MultipartReader() == nil {
			return nil, fmt.Errorf("no text/plain part found")
		}

		part, err := msg.MultipartReader().NextPart()
		if err == io.EOF {
			return nil, fmt.Errorf("no text/plain part found")
		}
		if err != nil {
			return nil, err
		}

		msg = part
	}
}

func (s *SoraSession) Copy(seqSet imap.NumSet, mboxName string) (*imap.CopyData, error) {
	if s.mailbox == nil {
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: "no mailbox selected",
		}
	}

	ctx := context.Background()

	pathComponents := strings.Split(mboxName, string(consts.MailboxDelimiter))
	destMailbox, err := s.server.db.GetMailboxByFullPath(ctx, s.user.userID, pathComponents)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNonExistent,
				Text: fmt.Sprintf("destination mailbox '%s' does not exist", mboxName),
			}
		}
		return nil, newInternalServerError("failed to fetch destination mailbox '%s': %v", mboxName, err)
	}

	messages, err := s.server.db.GetMessagesBySeqSet(ctx, s.mailbox.ID, seqSet)
	if err != nil {
		return nil, newInternalServerError("failed to retrieve messages for copy: %v", err)
	}

	var sourceUIDs imap.UIDSet
	var destUIDs imap.UIDSet
	for _, msg := range messages {
		sourceUIDs.AddNum(imap.UID(msg.ID))
		copiedUID, err := s.server.db.InsertMessageCopy(ctx, destMailbox.ID, imap.UID(msg.ID), func(destUID imap.UID) error {
			// Copy message body from source mailbox to destination mailbox in S3
			srcUUIDKey, err := uuid.Parse(msg.S3UUID)
			if err != nil {
				return newInternalServerError("failed to parse message UUID: %v", err)
			}
			destUUID := uuid.New()
			sourceS3Key := S3Key(s.user, srcUUIDKey)
			destS3Key := S3Key(s.user, destUUID)
			err = s.server.s3.CopyMessage(sourceS3Key, destS3Key)
			if err != nil {
				return newInternalServerError("failed to copy message body in S3: %v", err)
			}
			return nil
		})
		if err != nil {
			return nil, newInternalServerError("failed to insert copied message: %v", err)
		}
		destUIDs.AddNum(imap.UID(copiedUID))
	}

	copyData := &imap.CopyData{
		UIDValidity: destMailbox.UIDValidity,
		SourceUIDs:  sourceUIDs,
		DestUIDs:    destUIDs,
	}

	return copyData, nil
}

func (s *SoraSession) Expunge(w *imapserver.ExpungeWriter, uidSet *imap.UIDSet) error {
	ctx := context.Background()

	// Fetch the list of messages marked as \Deleted in the selected mailbox
	messages, err := s.server.db.GetMessagesByFlag(ctx, s.mailbox.ID, imap.FlagDeleted)
	if err != nil {
		return fmt.Errorf("failed to fetch deleted messages: %v", err)
	}

	// If an UIDSet is provided, filter the messages to match the UIDs
	var expungeIDs []uint32
	if uidSet != nil {
		for _, msg := range messages {
			if uidSet.Contains(imap.UID(msg.ID)) {
				expungeIDs = append(expungeIDs, uint32(msg.ID))
			}
		}
	} else {
		for _, msg := range messages {
			expungeIDs = append(expungeIDs, uint32(msg.ID))
		}
	}

	for _, uid := range expungeIDs {
		if err := w.WriteExpunge(uid); err != nil {
			return fmt.Errorf("failed to write expunge response for UID %d: %v", uid, err)
		}
	}

	// Perform the actual expunge operation
	err = s.server.db.ExpungeMessagesByUIDs(ctx, s.mailbox.ID, expungeIDs)
	if err != nil {
		return fmt.Errorf("failed to expunge messages: %v", err)
	}

	return nil
}

func (s *SoraSession) List(w *imapserver.ListWriter, ref string, patterns []string, options *imap.ListOptions) error {
	ctx := context.Background()

	// Determine whether to list subscribed mailboxes
	subscribed := options != nil && options.SelectSubscribed

	// Fetch mailboxes from the database
	var mailboxes []db.Mailbox
	var err error
	if subscribed {
		mailboxes, err = s.server.db.GetSubscribedMailboxes(ctx, s.user.userID)
	} else {
		mailboxes, err = s.server.db.GetMailboxes(ctx, s.user.userID)
	}
	if err != nil {
		return newInternalServerError("failed to list mailboxes: %v", err)
	}

	for _, pattern := range patterns {
		// Resolve the pattern against the reference name
		resolvedPattern := resolveMailboxPattern(ref, pattern)

		for _, mbox := range mailboxes {
			if matchMailboxName(resolvedPattern, mbox.Name) {
				// Prepare attributes
				attributes := []imap.MailboxAttr{}

				// Check if the mailbox has children
				hasChildren, err := s.server.db.MailboxHasChildren(ctx, mbox.ID)
				if err != nil {
					return newInternalServerError("failed to check mailbox children: %v", err)
				}

				if hasChildren {
					attributes = append(attributes, imap.MailboxAttrHasChildren)
				} else {
					attributes = append(attributes, imap.MailboxAttrHasNoChildren)
				}

				// Add special attributes
				switch strings.ToUpper(mbox.Name) {
				case "SENT":
					attributes = append(attributes, imap.MailboxAttrSent)
				case "TRASH":
					attributes = append(attributes, imap.MailboxAttrTrash)
				case "DRAFTS":
					attributes = append(attributes, imap.MailboxAttrDrafts)
				case "ARCHIVE":
					attributes = append(attributes, imap.MailboxAttrArchive)
				case "JUNK":
					attributes = append(attributes, imap.MailboxAttrJunk)
				}

				fullMailboxPath := mbox.Name
				if mbox.ParentID != nil {
					fullMailboxPath = *mbox.ParentPath + string(consts.MailboxDelimiter) + mbox.Name
				}

				listData := &imap.ListData{
					Mailbox: fullMailboxPath,
					Delim:   consts.MailboxDelimiter,
					Attrs:   attributes,
				}

				if err := w.WriteList(listData); err != nil {
					return newInternalServerError("failed to write mailbox data: %v", err)
				}
			}
		}
	}

	return nil
}

// Helper function to resolve mailbox patterns
func resolveMailboxPattern(ref, pattern string) string {
	// If pattern starts with hierarchy delimiter, ignore ref
	if len(pattern) > 0 && rune(pattern[0]) == consts.MailboxDelimiter {
		return pattern
	}
	// If ref is empty, return pattern
	if ref == "" {
		return pattern
	}
	// Combine ref and pattern with delimiter if needed
	combined := ref
	if len(ref) > 0 && rune(ref[len(ref)-1]) != consts.MailboxDelimiter {
		combined += string(consts.MailboxDelimiter)
	}
	combined += pattern
	return combined
}

// Helper function to match mailbox names against patterns
func matchMailboxName(pattern, name string) bool {
	// Replace IMAP wildcards with Go wildcards
	pattern = strings.ReplaceAll(pattern, "%", "*")
	pattern = strings.ReplaceAll(pattern, "*", ".*")

	// Compile the pattern into a regular expression
	regexPattern := "^" + pattern + "$"
	matched, err := regexp.MatchString(regexPattern, name)
	if err != nil {
		return false
	}
	return matched
}

func (s *SoraSession) Login(address, password string) error {
	address = strings.ToLower(address)
	addressParts := strings.Split(address, "@")
	if len(addressParts) != 2 {
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeAuthenticationFailed,
			Text: "Username not in the correct format",
		}
	}
	localPart := addressParts[0]
	domain := addressParts[1]

	log.Printf("Authentication attempt for user: %s", address)
	ctx := context.Background()

	userID, err := s.server.db.Authenticate(ctx, address, password)
	if err != nil {
		// Log the detailed error for debugging purposes
		log.Printf("Authentication failed for user %s: %v", address, err)

		// Return a specific authentication error
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeAuthenticationFailed,
			Text: "Invalid username or password",
		}
	}

	// Ensure default mailboxes are created for the user
	err = s.server.db.CreateDefaultMailboxes(ctx, userID)
	if err != nil {
		return newInternalServerError("failed to create default mailboxes: %v", err)
	}

	// If authentication is successful, set the user for this session
	s.user = &SoraUser{
		address:   address,
		localPart: localPart,
		domain:    domain,
		userID:    userID,
	}

	log.Printf("User %s successfully authenticated", address)
	return nil
}

func (s *SoraSession) Search(numKind imapserver.NumKind, criteria *imap.SearchCriteria, options *imap.SearchOptions) (*imap.SearchData, error) {
	ctx := context.Background()

	messages, err := s.server.db.GetMessagesWithCriteria(ctx, s.mailbox.ID, numKind, criteria)
	if err != nil {
		return nil, newInternalServerError("failed to search messages: %v", err)
	}

	var ids []uint32
	for _, msg := range messages {
		ids = append(ids, uint32(msg.ID)) // Collect the message IDs (UIDs)
	}

	searchData := &imap.SearchData{
		All:   imap.SeqSetNum(ids...),           // Initialize the NumSet with the collected IDs
		UID:   numKind == imapserver.NumKindUID, // Set UID flag if searching by UID
		Count: uint32(len(ids)),                 // Set the count of matching messages
	}

	searchData.Count = uint32(len(messages))

	return searchData, nil
}

func (s *SoraSession) Select(mboxName string, options *imap.SelectOptions) (*imap.SelectData, error) {
	ctx := context.Background()

	pathComponents := strings.Split(mboxName, string(consts.MailboxDelimiter))
	mailbox, err := s.server.db.GetMailboxByFullPath(ctx, s.user.userID, pathComponents)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNonExistent,
				Text: fmt.Sprintf("mailbox '%s' does not exist", mboxName),
			}
		}

		return nil, newInternalServerError("failed to fetch mailbox '%s': %v", mboxName, err)
	}

	messageCount, err := s.server.db.GetMessageCount(ctx, mailbox.ID)
	if err != nil {
		return nil, newInternalServerError("failed to get message count for mailbox '%s': %v", mboxName, err)
	}

	uidNext, err := s.server.db.GetMailboxNextUID(ctx, mailbox.ID)
	if err != nil {
		return nil, newInternalServerError("failed to get next UID for mailbox '%s': %v", mboxName, err)
	}

	s.mailbox = &SoraMailbox{
		name:        mboxName,
		ID:          mailbox.ID,
		uidValidity: mailbox.UIDValidity,
		uidNext:     uidNext,
		subscribed:  mailbox.Subscribed,
		readOnly:    options.ReadOnly,
	}

	selectData := &imap.SelectData{
		Flags:       s.mailbox.PermittedFlags(),
		NumMessages: uint32(messageCount),
		UIDNext:     imap.UID(uidNext),
		UIDValidity: mailbox.UIDValidity,
	}

	return selectData, nil
}

func (s *SoraSession) Unselect() error {
	s.mailbox = nil
	log.Printf("Mailbox unselected for user: %s", s.user.Address())
	return nil
}

func (s *SoraSession) Status(mboxName string, options *imap.StatusOptions) (*imap.StatusData, error) {
	ctx := context.Background()
	pathComponents := strings.Split(mboxName, string(consts.MailboxDelimiter))
	mailbox, err := s.server.db.GetMailboxByFullPath(ctx, s.user.userID, pathComponents)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNonExistent,
				Text: fmt.Sprintf("mailbox '%s' does not exist", mboxName),
			}
		}
		return nil, newInternalServerError("failed to fetch mailbox '%s': %v", mboxName, err)
	}

	statusData := &imap.StatusData{
		Mailbox: mailbox.Name,
	}

	if options.NumMessages {
		messageCount, err := s.server.db.GetMessageCount(ctx, mailbox.ID)
		if err != nil {
			return nil, newInternalServerError("failed to get message count for mailbox '%s': %v", mboxName, err)
		}
		numMessages := uint32(messageCount)
		statusData.NumMessages = &numMessages
	}

	if options.UIDNext {
		uidNext, err := s.server.db.GetMailboxNextUID(ctx, mailbox.ID)
		if err != nil {
			return nil, newInternalServerError("failed to get next UID for mailbox '%s': %v", mboxName, err)
		}
		statusData.UIDNext = imap.UID(uidNext)
	}

	if options.UIDValidity {
		statusData.UIDValidity = mailbox.UIDValidity
	}

	if options.NumUnseen {
		unseenCount, err := s.server.db.GetMailboxUnseenCount(ctx, mailbox.ID)
		if err != nil {
			return nil, newInternalServerError("failed to get unseen message count for mailbox '%s': %v", mboxName, err)
		}
		numUnseen := uint32(unseenCount)
		statusData.NumUnseen = &numUnseen
	}

	return statusData, nil
}

func (s *SoraSession) Close() error {
	if s.user != nil {
		log.Printf("Closing session for user: %v", s.user.address)
		s.user = nil
	}
	s.mailbox = nil
	return nil
}

/***************************************************************************************
 * Mailbox management
 ***************************************************************************************/

// Create a new mailbox
func (s *SoraSession) Create(name string, options *imap.CreateOptions) error {
	ctx := context.Background()

	// Split the mailbox name by the delimiter to check if it's nested
	parts := strings.Split(name, string(consts.MailboxDelimiter))

	// Check if this is a nested mailbox (i.e., it has a parent)
	if len(parts) > 1 {
		lastComponent := parts[len(parts)-1]

		parentPathComponents := parts[:len(parts)-1]
		parentPath := strings.Join(parentPathComponents, string(consts.MailboxDelimiter))

		parentMailbox, err := s.server.db.GetMailboxByFullPath(ctx, s.user.userID, parentPathComponents)
		if err != nil {
			if err == consts.ErrMailboxNotFound {
				return &imap.Error{
					Type: imap.StatusResponseTypeNo,
					Code: imap.ResponseCodeNonExistent,
					Text: fmt.Sprintf("parent mailbox '%s' does not exist", parentPath),
				}
			}
			return newInternalServerError("failed to fetch parent mailbox '%s': %v", parentPath, err)
		}

		err = s.server.db.CreateChildMailbox(ctx, s.user.userID, lastComponent, parentMailbox.ID, parentPath)
		if err != nil {
			return newInternalServerError("failed to create mailbox '%s': %v", name, err)
		}
		return nil
	}

	err := s.server.db.CreateMailbox(ctx, s.user.userID, name)
	if err != nil {
		return newInternalServerError("failed to create mailbox '%s': %v", name, err)
	}
	return nil
}

// Delete a mailbox
func (s *SoraSession) Delete(mboxName string) error {
	ctx := context.Background()

	for _, specialMailbox := range consts.DefaultMailboxes {
		if strings.EqualFold(mboxName, specialMailbox) {
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNoPerm,
				Text: fmt.Sprintf("Mailbox '%s' is a special mailbox and cannot be deleted", mboxName),
			}
		}
	}

	pathComponents := strings.Split(mboxName, string(consts.MailboxDelimiter))

	// Fetch the mailbox from the database using the full path
	mailbox, err := s.server.db.GetMailboxByFullPath(ctx, s.user.userID, pathComponents)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNonExistent,
				Text: fmt.Sprintf("Mailbox '%s' not found", mboxName),
			}
		}
		return newInternalServerError("failed to fetch mailbox '%s': %v", mboxName, err)
	}

	// Delete the mailbox; the database will automatically delete any child mailboxes due to ON DELETE CASCADE
	err = s.server.db.DeleteMailbox(ctx, mailbox.ID, mboxName)
	if err != nil {
		return newInternalServerError("failed to delete mailbox '%s': %v", mboxName, err)
	}

	return nil
}

// Rename a mailbox
func (s *SoraSession) Rename(existingName, newName string) error {
	log.Printf("Rename request: %s -> %s", existingName, newName)

	if existingName == newName {
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeAlreadyExists,
			Text: "The new mailbox name is the same as the current one.",
		}
	}

	ctx := context.Background()
	// Fetch the old mailbox based on its current name
	oldMailboxPathComponents := strings.Split(existingName, string(consts.MailboxDelimiter))
	oldMailbox, err := s.server.db.GetMailboxByFullPath(ctx, s.user.userID, oldMailboxPathComponents)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNonExistent,
				Text: fmt.Sprintf("mailbox '%s' does not exist", existingName),
			}
		}
		return newInternalServerError("failed to fetch mailbox '%s': %v", existingName, err)
	}

	// Parse new mailbox path components
	newMailboxPathComponents := strings.Split(newName, string(consts.MailboxDelimiter))
	var newParentPath *string

	// Check if the new mailbox name has a parent
	if len(newMailboxPathComponents) > 1 {
		parentMailboxComponents := newMailboxPathComponents[:len(newMailboxPathComponents)-1]
		newName = newMailboxPathComponents[len(newMailboxPathComponents)-1]

		// Check if the parent mailbox of the new name exists
		_, err = s.server.db.GetMailboxByFullPath(ctx, s.user.userID, parentMailboxComponents)
		if err != nil {
			if err == consts.ErrMailboxNotFound {
				return &imap.Error{
					Type: imap.StatusResponseTypeNo,
					Code: imap.ResponseCodeNonExistent,
					Text: fmt.Sprintf("parent mailbox for '%s' does not exist", newName),
				}
			}
			return newInternalServerError("failed to check parent mailbox for '%s': %v", newName, err)
		}
		newParentPathStr := JoinMailboxPath(parentMailboxComponents)
		newParentPath = &newParentPathStr
	}

	// Perform the rename operation
	err = s.server.db.RenameMailbox(ctx, oldMailbox.ID, newName, newParentPath)
	if err != nil {
		return newInternalServerError("failed to rename mailbox '%s' to '%s': %v", existingName, newName, err)
	}

	log.Printf("Renamed mailbox: %s -> %s", existingName, newName)
	return nil
}

// Subscribe to a mailbox
func (s *SoraSession) Subscribe(mailboxName string) error {
	return s.updateSubscriptionStatus(mailboxName, true)
}

// Unsubscribe from a mailbox
func (s *SoraSession) Unsubscribe(mailboxName string) error {
	return s.updateSubscriptionStatus(mailboxName, false)
}

// Helper function to handle both subscribe and unsubscribe logic
func (s *SoraSession) updateSubscriptionStatus(mailboxName string, subscribe bool) error {
	ctx := context.Background()
	pathComponents := strings.Split(mailboxName, string(consts.MailboxDelimiter))

	// Fetch the mailbox by its full path
	mailbox, err := s.server.db.GetMailboxByFullPath(ctx, s.user.userID, pathComponents)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNonExistent,
				Text: fmt.Sprintf("mailbox '%s' does not exist", mailboxName),
			}
		}
		return newInternalServerError("failed to fetch mailbox '%s': %v", mailboxName, err)
	}

	// Set subscription status
	err = s.server.db.SetSubscribed(ctx, mailbox.ID, subscribe)
	if err != nil {
		log.Printf("Failed to set mailbox subscription status: %v", err)
		return newInternalServerError("failed to set subscription status for mailbox '%s': %v", mailboxName, err)
	}

	action := "subscribed"
	if !subscribe {
		action = "unsubscribed"
	}
	log.Printf("Mailbox %s: %s", action, mailboxName)

	return nil
}

/***************************************************************************************
 * Message management
 ***************************************************************************************/

func (s *SoraSession) Fetch(w *imapserver.FetchWriter, seqSet imap.NumSet, options *imap.FetchOptions) error {
	ctx := context.Background()

	messages, err := s.server.db.GetMessagesBySeqSet(ctx, s.mailbox.ID, seqSet)
	if err != nil {
		return newInternalServerError("failed to retrieve messages: %v", err)
	}

	for _, msg := range messages {
		if err := s.fetchMessage(w, &msg, options); err != nil {
			return err
		}
	}

	return nil
}

func (s *SoraSession) fetchMessage(w *imapserver.FetchWriter, msg *db.Message, options *imap.FetchOptions) error {
	m := w.CreateMessage(uint32(msg.ID))
	if m == nil {
		return newInternalServerError("failed to begin message for UID %d", msg.ID)
	}

	if err := s.writeBasicMessageData(m, msg, options); err != nil {
		return err
	}

	if options.Envelope {
		if err := s.writeEnvelope(m, msg.ID); err != nil {
			return err
		}
	}

	if options.BodyStructure != nil {
		if err := s.writeBodyStructure(m, msg.ID); err != nil {
			return err
		}
	}

	if len(options.BodySection) > 0 || len(options.BinarySection) > 0 || len(options.BinarySectionSize) > 0 {
		s3UUIDKey, err := uuid.Parse(msg.S3UUID)
		if err != nil {
			return newInternalServerError("failed to parse message UUID: %v", err)
		}
		s3Key := S3Key(s.user, s3UUIDKey)

		log.Printf("Fetching message body for UID %d", msg.ID)
		bodyReader, err := s.server.s3.GetMessage(s3Key)
		if err != nil {
			return newInternalServerError("failed to retrieve message body for UID %d from S3: %v", msg.ID, err)
		}
		defer bodyReader.Close()
		log.Printf("Retrieved message body for UID %d", msg.ID)

		bodyData, err := io.ReadAll(bodyReader)
		if err != nil {
			return newInternalServerError("failed to read message body for UID %d: %v", msg.ID, err)
		}

		if len(options.BodySection) > 0 {
			if err := s.handleBodySections(m, msg.ID, bodyData, options); err != nil {
				return err
			}
		}

		if len(options.BinarySection) > 0 {
			if err := s.handleBinarySections(m, msg.ID, bodyData, options); err != nil {
				return err
			}
		}

		if len(options.BinarySectionSize) > 0 {
			if err := s.handleBinarySectionSize(m, msg.ID, bodyData, options); err != nil {
				return err
			}
		}
	}

	// TODO: Fetch ModSeq (if CONDSTORE is supported)

	if err := m.Close(); err != nil {
		return fmt.Errorf("failed to end message for UID %d: %v", msg.ID, err)
	}

	return nil
}

// Fetch helper to write basic message data (FLAGS, UID, INTERNALDATE, RFC822.SIZE)
func (s *SoraSession) writeBasicMessageData(m *imapserver.FetchResponseWriter, msg *db.Message, options *imap.FetchOptions) error {
	if options.Flags {
		m.WriteFlags(db.BitwiseToFlags(msg.BitwiseFlags))
	}
	if options.UID {
		m.WriteUID(imap.UID(msg.ID))
	}
	if options.InternalDate {
		m.WriteInternalDate(msg.InternalDate)
	}
	if options.RFC822Size {
		m.WriteRFC822Size(int64(msg.Size))
	}
	return nil
}

// Fetch helper to write the envelope for a message
func (s *SoraSession) writeEnvelope(m *imapserver.FetchResponseWriter, messageID int) error {
	ctx := context.Background()
	envelope, err := s.server.db.GetMessageEnvelope(ctx, messageID)
	if err != nil {
		return newInternalServerError("failed to retrieve envelope for message UID %d: %v", messageID, err)
	}
	m.WriteEnvelope(envelope)
	return nil
}

// Fetch helper to write the body structure for a message
func (s *SoraSession) writeBodyStructure(m *imapserver.FetchResponseWriter, messageID int) error {
	ctx := context.Background()
	bodyStructure, err := s.server.db.GetMessageBodyStructure(ctx, messageID)
	if err != nil {
		return newInternalServerError("failed to retrieve body structure for message UID %d: %v", messageID, err)
	}
	m.WriteBodyStructure(*bodyStructure)
	return nil
}

func getMessageReader(messageID int, bodyData []byte) (*message.Entity, error) {
	mr, err := message.Read(bytes.NewReader(bodyData))
	if message.IsUnknownCharset(err) {
		log.Println("Unknown encoding:", err)
	} else if err != nil {
		return nil, newInternalServerError("failed to parse message UID %d: %v", messageID, err)
	}
	return mr, nil
}

// Fetch helper to handle BINARY sections for a message
func (s *SoraSession) handleBinarySections(m *imapserver.FetchResponseWriter, messageID int, bodyData []byte, options *imap.FetchOptions) error {
	for _, binarySection := range options.BinarySection {
		parsedMessage, err := getMessageReader(messageID, bodyData)
		if err != nil {
			return err
		}

		part, err := helpers.ExtractPart(parsedMessage, binarySection.Part[0]) // Only pass a single part
		if err != nil {
			return newInternalServerError("failed to extract binary part for UID %d: %v", messageID, err)
		}

		var binaryBuf bytes.Buffer
		tee := io.TeeReader(part.Body, &binaryBuf)

		binarySize, err := io.Copy(io.Discard, tee)
		if err != nil {
			return newInternalServerError("failed to calculate size of binary section for UID %d: %v", messageID, err)
		}

		fetchBinarySection := &imap.FetchItemBinarySection{
			Part:    binarySection.Part,    // Pass the part number
			Partial: binarySection.Partial, // Handle partial fetch
			Peek:    binarySection.Peek,    // Peek flag
		}

		if err := m.WriteBinarySection(fetchBinarySection, binarySize); err != nil {
			return newInternalServerError("failed to write binary section for UID %d: %v", messageID, err)
		}
	}
	return nil
}

// Fetch helper to handle BINARY.SIZE sections for a message
func (s *SoraSession) handleBinarySectionSize(m *imapserver.FetchResponseWriter, messageID int, bodyData []byte, options *imap.FetchOptions) error {
	for _, binarySectionSize := range options.BinarySectionSize {
		parsedMessage, err := getMessageReader(messageID, bodyData)
		if err != nil {
			return err
		}

		part, err := helpers.ExtractPart(parsedMessage, binarySectionSize.Part[0]) // Extract the part
		if err != nil {
			return newInternalServerError("failed to extract binary section size for UID %d: %v", messageID, err)
		}

		var partBuf bytes.Buffer
		if _, err := io.Copy(&partBuf, part.Body); err != nil {
			return newInternalServerError("failed to calculate size of binary section for UID %d: %v", messageID, err)
		}

		size := uint32(partBuf.Len())

		fetchBinarySection := &imap.FetchItemBinarySection{
			Part: binarySectionSize.Part,
		}

		m.WriteBinarySectionSize(fetchBinarySection, size)
	}
	return nil
}

// Fetch helper to handle BODY sections for a message
func (s *SoraSession) handleBodySections(m *imapserver.FetchResponseWriter, messageID int, bodyData []byte, options *imap.FetchOptions) error {
	for _, section := range options.BodySection {
		parsedMessage, err := getMessageReader(messageID, bodyData)
		if err != nil {
			return err
		}

		if len(section.Part) > 0 {
			partNum := section.Part[0]
			part, err := helpers.ExtractPart(parsedMessage, partNum)
			if err != nil {
				// Instead of returning an error, we'll write an empty section
				bodyWriter := m.WriteBodySection(section, 0)
				if bodyWriter != nil {
					bodyWriter.Close()
				}
				continue
			}

			switch section.Specifier {
			case imap.PartSpecifierMIME:
				// Handle MIME headers -----
				var mimeHeaderBuilder strings.Builder
				for field := part.Header.Fields(); field.Next(); {
					k := field.Key()
					v := field.Value()
					fmt.Fprintf(&mimeHeaderBuilder, "%s: %s\r\n", k, v)
				}
				mimeHeaders := mimeHeaderBuilder.String() + "\r\n"
				mimeHeadersSize := int64(len(mimeHeaders))

				bodyWriter := m.WriteBodySection(section, mimeHeadersSize)
				if bodyWriter == nil {
					return newInternalServerError("failed to begin writing body section (MIME) for UID %d", messageID)
				}

				if _, err := bodyWriter.Write([]byte(mimeHeaders)); err != nil {
					return newInternalServerError("failed to write MIME headers for UID %d: %v", messageID, err)
				}

				if err := bodyWriter.Close(); err != nil {
					return newInternalServerError("failed to close body section writer (MIME) for UID %d: %v", messageID, err)
				}

			case imap.PartSpecifierHeader:
				var mimeHeaderBuilder strings.Builder
				for field := part.Header.Fields(); field.Next(); {
					k := field.Key()
					v := field.Value()
					fmt.Fprintf(&mimeHeaderBuilder, "%s: %s\r\n", k, v)
				}
				mimeHeaders := mimeHeaderBuilder.String() + "\r\n"
				mimeHeadersSize := int64(len(mimeHeaders))

				bodyWriter := m.WriteBodySection(&imap.FetchItemBodySection{
					Specifier:    imap.PartSpecifierHeader,
					HeaderFields: section.HeaderFields,
				}, mimeHeadersSize)

				if bodyWriter == nil {
					return newInternalServerError("failed to begin writing headers for UID %d", messageID)
				}

				if _, err := bodyWriter.Write([]byte(mimeHeaders)); err != nil {
					return newInternalServerError("failed to write headers for UID %d: %v", messageID, err)
				}

				if err := bodyWriter.Close(); err != nil {
					return newInternalServerError("failed to close header writer for UID %d: %v", messageID, err)
				}

			case imap.PartSpecifierText:
				// Handle TEXT request (extract and write the text body part)
				textBodyPart, err := helpers.ExtractPart(parsedMessage, 1) // Assuming the main text body is part 1
				if err != nil {
					return newInternalServerError("failed to extract text body part for UID %d: %v", messageID, err)
				}

				var textBodyBuf bytes.Buffer
				if _, err := io.Copy(&textBodyBuf, textBodyPart.Body); err != nil {
					return newInternalServerError("failed to buffer text body for UID %d: %v", messageID, err)
				}

				textBody := textBodyBuf.Bytes() // Get the byte slice from the buffer
				textBodySize := int64(textBodyBuf.Len())

				bodyWriter := m.WriteBodySection(section, textBodySize)
				if bodyWriter == nil {
					return newInternalServerError("failed to begin writing body section (TEXT) for UID %d", messageID)
				}

				textBodyReader := bytes.NewReader(textBody)
				if _, err := io.Copy(bodyWriter, textBodyReader); err != nil {
					return newInternalServerError("failed to write text body for UID %d: %v", messageID, err)
				}

				if err := bodyWriter.Close(); err != nil {
					return newInternalServerError("failed to close body section writer (TEXT) for UID %d: %v", messageID, err)
				}

			default:
				// UID FETCH <uid> BODY[<section>]
				// Create a new TeeReader to calculate the size and keep a copy for writing
				var partBuf bytes.Buffer
				partTee := io.TeeReader(part.Body, &partBuf)

				// Calculate the size of the body part
				bodySize, err := io.Copy(io.Discard, partTee)
				if err != nil {
					return newInternalServerError("failed to calculate size of part for UID %d: %v", messageID, err)
				}

				// Create a FetchItemBodySection for WriteBodySection
				fetchSection := &imap.FetchItemBodySection{
					Part:            section.Part,            // Part number
					HeaderFields:    section.HeaderFields,    // Requested header fields
					HeaderFieldsNot: section.HeaderFieldsNot, // Excluded header fields
					Partial:         section.Partial,         // Partial fetching details (Offset, Size)
					Peek:            section.Peek,            // Whether to peek (no change in \Seen flag)
				}

				// Now, write the body section using the buffered data in partBuf
				bodyWriter := m.WriteBodySection(fetchSection, bodySize)
				if bodyWriter == nil {
					return newInternalServerError("failed to begin writing body section for UID %d", messageID)
				}
				// Write the actual body data
				if _, err := bodyWriter.Write(partBuf.Bytes()); err != nil {
					return newInternalServerError("failed to write body section data for UID %d: %v", messageID, err)
				}

				// Close the writer
				if err := bodyWriter.Close(); err != nil {
					return newInternalServerError("failed to close body section writer for UID %d: %v", messageID, err)
				}
			}
		} else {
			if section.Specifier == imap.PartSpecifierHeader {
				var headers bytes.Buffer
				if section.HeaderFields != nil {
					// Specific headers requested
					for _, reqField := range section.HeaderFields {
						for field := parsedMessage.Header.Fields(); field.Next(); {
							k := field.Key()
							if strings.EqualFold(reqField, k) {
								v := field.Value()
								fmt.Fprintf(&headers, "%s: %s\r\n", k, v)
							}
						}
					}
				} else {
					// Full headers requested
					for field := parsedMessage.Header.Fields(); field.Next(); {
						k := field.Key()
						v := field.Value()
						fmt.Fprintf(&headers, "%s: %s\r\n", k, v)
					}
				}
				headersData := headers.Bytes()
				headersSize := int64(len(headersData))

				bodyWriter := m.WriteBodySection(section, headersSize)
				if bodyWriter == nil {
					return newInternalServerError("failed to begin writing headers for UID %d", messageID)
				}

				if _, err := bodyWriter.Write(headersData); err != nil {
					return newInternalServerError("failed to write headers for UID %d: %v", messageID, err)
				}

				if err := bodyWriter.Close(); err != nil {
					return newInternalServerError("failed to close header writer for UID %d: %v", messageID, err)
				}
			} else {
				// ? UID FETCH <uid> BODY[]
				//
				// Write the entire body if no part is specified (and it's not a HEADER request)
				bodyWriter := m.WriteBodySection(&imap.FetchItemBodySection{}, int64(len(bodyData)))
				if bodyWriter == nil {
					return newInternalServerError("failed to begin writing body section for UID %d", messageID)
				}
				// Write the actual body data
				if _, err := bodyWriter.Write(bodyData); err != nil {
					return newInternalServerError("failed to write body section data for UID %d: %v", messageID, err)
				}

				// Close the writer
				if err := bodyWriter.Close(); err != nil {
					return newInternalServerError("failed to close body section writer for UID %d: %v", messageID, err)
				}
			}
			continue
		}
	}
	return nil
}

// Update flags for messages in the selected mailbox
func (s *SoraSession) Store(w *imapserver.FetchWriter, seqSet imap.NumSet, flags *imap.StoreFlags, options *imap.StoreOptions) error {
	if s.mailbox == nil {
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: "no mailbox selected",
		}
	}

	ctx := context.Background()
	messages, err := s.server.db.GetMessagesBySeqSet(ctx, s.mailbox.ID, seqSet)
	if err != nil {
		return newInternalServerError("failed to retrieve messages: %v", err)
	}

	for _, msg := range messages {
		var newFlags *[]imap.Flag
		switch flags.Op {
		case imap.StoreFlagsAdd:
			newFlags, err = s.server.db.AddMessageFlags(ctx, msg.ID, flags.Flags)
		case imap.StoreFlagsDel:
			newFlags, err = s.server.db.RemoveMessageFlags(ctx, msg.ID, flags.Flags)
		case imap.StoreFlagsSet:
			newFlags, err = s.server.db.SetMessageFlags(ctx, msg.ID, flags.Flags)
		}

		if err != nil {
			return newInternalServerError("failed to update flags for message: %v", err)
		}

		// newFlags := db.BitwiseToFlags(newFlagsInt)
		m := w.CreateMessage(uint32(msg.ID))
		if !flags.Silent {
			m.WriteFlags(*newFlags)
		}
		m.Close()
	}
	return nil
}

func (s *SoraSession) Idle(w *imapserver.UpdateWriter, done <-chan struct{}) error {
	log.Println("Client entered IDLE mode")

	// Check if a mailbox is selected for this session
	mailbox := s.mailbox
	if mailbox == nil {
		return fmt.Errorf("no mailbox selected for IDLE mode")
	}

	// // Start a goroutine to listen for changes in the mailbox
	updateChan := make(chan imapserver.UpdateWriter) // Channel to receive updates

	go func() {
		for {
			select {
			case <-done:
				// Client sent DONE, exit idle mode
				log.Println("Client exited IDLE mode")
				close(updateChan) // Close the update channel
				return

				// case newMessageCount := <-s.server.db.ListenForNewMessages(mailbox.ID):
				// 	// Notify the client of new messages
				// 	if err := w.WriteExists(newMessageCount); err != nil {
				// 		log.Printf("Failed to notify about new messages: %v", err)
				// 	}

				// case expungedSeqNum := <-s.server.db.ListenForExpungedMessages(mailbox.ID):
				// 	// Notify the client of expunged messages
				// 	if err := w.WriteExpunge(expungedSeqNum); err != nil {
				// 		log.Printf("Failed to notify about expunged messages: %v", err)
				// 	}

				// case flagUpdate := <-s.server.db.ListenForFlagUpdates(mailbox.ID):
				// 	// Notify the client of flag updates
				// 	if err := w.WriteFlags(flagUpdate.SeqNum, flagUpdate.Flags); err != nil {
				// 		log.Printf("Failed to notify about flag updates: %v", err)
				// 	}
			}
		}
	}()

	// // Block until the client sends DONE
	<-done

	return nil
}

func (s *SoraSession) Poll(w *imapserver.UpdateWriter, b bool) error {
	if s.mailbox == nil {
		// TODO: Why is poll called if no mailbox is selected? E.g. LIST will call poll, why?
		return nil
	}

	ctx := context.Background()
	updates, numMessages, err := s.server.db.GetMailboxUpdates(ctx, s.mailbox.ID, s.mailbox.lastPollAt)
	if err != nil {
		return newInternalServerError("failed to get mailbox updates: %v", err)
	}

	s.mailbox.numMessages = numMessages

	for _, update := range updates {
		if update.IsExpunge {
			if err := w.WriteExpunge(uint32(update.SeqNum)); err != nil {
				return newInternalServerError("failed to write expunge update: %v", err)
			}
		} else if update.FlagsChanged {
			if err := w.WriteMessageFlags(uint32(update.SeqNum), imap.UID(update.ID), db.BitwiseToFlags(update.BitwiseFlags)); err != nil {
				return newInternalServerError("failed to write flag update: %v", err)
			}
		}
	}

	if err := w.WriteNumMessages(uint32(numMessages)); err != nil {
		return newInternalServerError("failed to write number of messages: %v", err)
	}

	s.mailbox.lastPollAt = time.Now()

	return nil
}

func (s *SoraSession) Namespace() (*imap.NamespaceData, error) {
	return nil, fmt.Errorf("Namespace not implemented")
}

func (s *SoraSession) Move(w *imapserver.MoveWriter, numSet imap.NumSet, dest string) error {
	// Ensure a mailbox is selected
	if s.mailbox == nil {
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: "no mailbox selected",
		}
	}

	ctx := context.Background()

	// Find the destination mailbox by its name
	destMailbox, err := s.server.db.GetMailboxByFullPath(ctx, s.user.userID, strings.Split(dest, string(consts.MailboxDelimiter)))
	if err != nil {
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: fmt.Sprintf("destination mailbox '%s' not found", dest),
		}
	}

	// Get messages by sequence or UID set (based on NumKind, which is SeqNum or UID)
	messages, err := s.server.db.GetMessagesBySeqSet(ctx, s.mailbox.ID, numSet)
	if err != nil {
		return newInternalServerError("failed to retrieve messages: %v", err)
	}

	// Collect message IDs for moving and sequence numbers for expunge
	var sourceUIDs []imap.UID
	var seqNums []uint32
	var destUIDs []imap.UID

	for _, msg := range messages {
		sourceUIDs = append(sourceUIDs, imap.UID(msg.ID))
		seqNums = append(seqNums, uint32(msg.Seq))
	}

	// Move messages in the database
	messageUIDMap, err := s.server.db.MoveMessages(ctx, &sourceUIDs, s.mailbox.ID, destMailbox.ID)
	if err != nil {
		return newInternalServerError("failed to move messages: %v", err)
	}

	// messageUIDMap holds the mapping between original UIDs and new UIDs
	for originalUID, newUID := range messageUIDMap {
		sourceUIDs = append(sourceUIDs, imap.UID(originalUID))
		destUIDs = append(destUIDs, imap.UID(newUID))
	}

	// Prepare CopyData (UID data for the COPYUID response)
	copyData := &imap.CopyData{
		UIDValidity: s.mailbox.uidValidity,         // UIDVALIDITY of the source mailbox
		SourceUIDs:  imap.UIDSetNum(sourceUIDs...), // Original UIDs (source mailbox)
		DestUIDs:    imap.UIDSetNum(destUIDs...),   // New UIDs in the destination mailbox
	}

	// Write the CopyData (COPYUID response)
	if err := w.WriteCopyData(copyData); err != nil {
		return newInternalServerError("failed to write COPYUID: %v", err)
	}

	// Expunge messages in the source mailbox (optional)
	for _, seqNum := range seqNums {
		if err := w.WriteExpunge(seqNum); err != nil {
			return newInternalServerError("failed to write EXPUNGE: %v", err)
		}
	}

	return nil
}
