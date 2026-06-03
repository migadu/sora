package imap

import (
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/db"
	"github.com/stretchr/testify/assert"
)

func TestThreadOrderedSubject(t *testing.T) {
	session := &IMAPSession{}

	now := time.Now()
	messages := []db.ThreadMessageResult{
		{UID: 1, Seq: 1, SubjectSort: "hello", SentDate: now.Add(-2 * time.Hour)},
		{UID: 2, Seq: 2, SubjectSort: "world", SentDate: now.Add(-1 * time.Hour)},
		{UID: 3, Seq: 3, SubjectSort: "hello", SentDate: now.Add(-1 * time.Hour)},
		{UID: 4, Seq: 4, SubjectSort: "apple", SentDate: now},
	}

	result := session.threadOrderedSubject(imapserver.NumKindUID, messages)

	// "hello" comes first chronologically because its earliest message (UID 1) is earliest.
	// "world" is next.
	// "apple" is last.

	assert.Len(t, result, 3)
	assert.Equal(t, []uint32{1, 3}, result[0].Chain, "Should group by subject and order by sent date")
	assert.Equal(t, []uint32{2}, result[1].Chain)
	assert.Equal(t, []uint32{4}, result[2].Chain)
}

func TestThreadReferences(t *testing.T) {
	session := &IMAPSession{}

	// Create a conversation thread
	// UID 1: Original message <A>
	// UID 2: Reply to <A> -> <B>
	// UID 3: Reply to <B> -> <C>
	// UID 4: Another Reply to <A> -> <D>
	// UID 5: Unrelated message -> <E>
	messages := []db.ThreadMessageResult{
		{UID: 1, Seq: 1, MessageID: "<A>", SentDate: time.Now().Add(-5 * time.Hour)},
		{UID: 2, Seq: 2, MessageID: "<B>", InReplyTo: "<A>", SentDate: time.Now().Add(-4 * time.Hour)},
		{UID: 3, Seq: 3, MessageID: "<C>", InReplyTo: "<B>", SentDate: time.Now().Add(-3 * time.Hour)},
		{UID: 4, Seq: 4, MessageID: "<D>", InReplyTo: "<A>", SentDate: time.Now().Add(-2 * time.Hour)},
		{UID: 5, Seq: 5, MessageID: "<E>", SentDate: time.Now().Add(-1 * time.Hour)},
	}

	result := session.threadReferences(imapserver.NumKindUID, messages, false)

	// Expected structure:
	// - Thread 1: Chain(1) -> SubThreads: Chain(2)->Chain(3) AND Chain(4)
	// - Thread 2: Chain(5)

	assert.Len(t, result, 2)

	// Thread 1
	thread1 := result[0]
	assert.Equal(t, []uint32{1}, thread1.Chain)
	assert.Len(t, thread1.SubThreads, 2)

	assert.Equal(t, []uint32{2, 3}, thread1.SubThreads[0].Chain, "Linear replies collapse into chain")
	assert.Equal(t, []uint32{4}, thread1.SubThreads[1].Chain)

	// Thread 2
	thread2 := result[1]
	assert.Equal(t, []uint32{5}, thread2.Chain)
}

func TestThreadReferences_SubjectGrouping(t *testing.T) {
	session := &IMAPSession{}

	// These messages have NO In-Reply-To or References connecting them.
	// However, they share the exact same base subject ("cron job failed").
	// RFC 5256 dictates that they MUST be grouped together in the final phase.
	messages := []db.ThreadMessageResult{
		{UID: 1, Seq: 1, MessageID: "<1@cron>", SubjectSort: "cron job failed", SentDate: time.Now().Add(-2 * time.Hour)},
		{UID: 2, Seq: 2, MessageID: "<2@cron>", SubjectSort: "cron job failed", SentDate: time.Now().Add(-1 * time.Hour)},
		{UID: 3, Seq: 3, MessageID: "<3@cron>", SubjectSort: "cron job failed", SentDate: time.Now()},
		{UID: 4, Seq: 4, MessageID: "<4@other>", SubjectSort: "unrelated", SentDate: time.Now()},
	}

	result := session.threadReferences(imapserver.NumKindUID, messages, false)

	// Since skipSubjectGrouping is false, messages 1, 2, and 3 should be grouped together under a dummy node.
	// Message 4 should be in its own thread.
	assert.Len(t, result, 2, "Messages sharing a subject should be grouped into a single thread")

	// Verify the cron jobs were grouped. Since they are grouped under a dummy node, the Chain should be empty
	// and they should exist as separate branches (SubThreads).
	cronThread := result[0]
	assert.Empty(t, cronThread.Chain)
	assert.Len(t, cronThread.SubThreads, 3)
	assert.Equal(t, []uint32{1}, cronThread.SubThreads[0].Chain)
	assert.Equal(t, []uint32{2}, cronThread.SubThreads[1].Chain)
	assert.Equal(t, []uint32{3}, cronThread.SubThreads[2].Chain)

	otherThread := result[1]
	assert.Equal(t, []uint32{4}, otherThread.Chain)

	// Now verify that skipSubjectGrouping=true bypasses this (THREAD=REFS behavior)
	resultRefs := session.threadReferences(imapserver.NumKindUID, messages, true)
	assert.Len(t, resultRefs, 4, "REFS should not group by subject, leaving 4 isolated root nodes")
}
