package consts

import "math"

// MaxStoredMessageSize is the largest message, in octets, sora can store:
// messages.size and pending_uploads.size are INTEGER columns, which refuse a
// larger value. Every size limit on a way in (IMAP append_limit, max_message_size
// of LMTP, the LMTP proxy and the Admin API delivery, the sora-admin import) is
// capped at it, so a larger message is refused before it is read rather than at
// the database insert.
const MaxStoredMessageSize = math.MaxInt32
