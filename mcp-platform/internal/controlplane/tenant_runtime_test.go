package controlplane

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestShouldRequeueDelete(t *testing.T) {
	t.Parallel()

	require.True(t, shouldRequeueDelete(nil))

	recent := time.Now().UTC().Add(-(deleteRequeueInterval / 2))
	require.False(t, shouldRequeueDelete(&recent))

	stale := time.Now().UTC().Add(-(deleteRequeueInterval + time.Second))
	require.True(t, shouldRequeueDelete(&stale))
}
