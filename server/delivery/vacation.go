package delivery

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/emersion/go-message"
	"github.com/emersion/go-message/mail"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/sieveengine"
)

// VacationHandler interface defines the contract for handling vacation responses.
type VacationHandler interface {
	HandleVacationResponse(ctx context.Context, AccountID int64, result sieveengine.Result, fromAddr *server.Address, toAddress *server.Address, originalMessage *message.Entity) error
}

// StandardVacationHandler implements the standard vacation response handling.
type StandardVacationHandler struct {
	Hostname     string
	RelayHandler RelayHandler
	RelayQueue   RelayQueue // Optional: disk-based queue for relay retry
	Logger       Logger
}

// HandleVacationResponse handles vacation auto-response.
func (h *StandardVacationHandler) HandleVacationResponse(ctx context.Context, AccountID int64, result sieveengine.Result, fromAddr *server.Address, toAddress *server.Address, originalMessage *message.Entity) error {
	if h.RelayHandler == nil && h.RelayQueue == nil {
		if h.Logger != nil {
			h.Logger.Log("[VACATION] external relay not configured, cannot send vacation response")
		}
		return nil
	}

	// Create vacation response message
	vacationFrom := toAddress.FullAddress()
	if result.VacationFrom != "" {
		vacationFrom = result.VacationFrom
	}

	vacationSubject := "Auto: Out of Office"
	if result.VacationSubj != "" {
		vacationSubject = result.VacationSubj
	}

	// Build vacation message
	var vacationMessage bytes.Buffer
	var msgHeader message.Header
	msgHeader.Set("From", vacationFrom)
	msgHeader.Set("To", fromAddr.FullAddress())
	msgHeader.Set("Subject", vacationSubject)
	msgHeader.Set("Message-ID", fmt.Sprintf("<%d.vacation@%s>", time.Now().UnixNano(), h.Hostname))
	msgHeader.Set("Auto-Submitted", "auto-replied")
	msgHeader.Set("X-Auto-Response-Suppress", "All")
	msgHeader.Set("Date", time.Now().Format(time.RFC1123Z))

	originalHeader := mail.Header{Header: originalMessage.Header}
	if originalMessageID, _ := originalHeader.MessageID(); originalMessageID != "" {
		msgHeader.Set("In-Reply-To", originalMessageID)
		msgHeader.Set("References", originalMessageID)
	}

	w, err := message.CreateWriter(&vacationMessage, msgHeader)
	if err != nil {
		return err
	}

	var textHeader message.Header
	textHeader.Set("Content-Type", "text/plain; charset=utf-8")
	textWriter, _ := w.CreatePart(textHeader)
	textWriter.Write([]byte(result.VacationMsg))
	textWriter.Close()
	w.Close()

	// Send via external relay or queue
	if h.RelayQueue != nil {
		// Queue for background delivery with retry
		err := h.RelayQueue.Enqueue(vacationFrom, fromAddr.FullAddress(), "vacation", vacationMessage.Bytes())
		if err != nil && h.Logger != nil {
			h.Logger.Log("[VACATION] Failed to enqueue vacation response: %v", err)
		}
		return err
	} else if h.RelayHandler != nil {
		return h.RelayHandler.SendToExternalRelay(vacationFrom, fromAddr.FullAddress(), vacationMessage.Bytes())
	}

	return nil
}
