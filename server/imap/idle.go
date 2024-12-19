package imap

import (
	"fmt"
	"log"

	"github.com/emersion/go-imap/v2/imapserver"
)

func (s *IMAPSession) Idle(w *imapserver.UpdateWriter, done <-chan struct{}) error {
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
