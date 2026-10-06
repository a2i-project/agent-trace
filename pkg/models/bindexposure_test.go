package models

import (
	"testing"
	"time"
)

func TestClassifyBindTarget(t *testing.T) {
	tests := []struct {
		target string
		want   Exposure
	}{
		{"127.0.0.1:8080", ExposureLoopback},
		{"127.5.5.5:1", ExposureLoopback},
		{"[::1]:8080", ExposureLoopback},
		{"[::ffff:127.0.0.1]:80", ExposureLoopback},
		{"0.0.0.0:8080", ExposureWildcard},
		{"[::]:8080", ExposureWildcard},
		{"10.1.2.3:22", ExposureInterface},
		{"[2001:db8::1]:443", ExposureInterface},
		{"unix:/var/run/docker.sock", ExposureLocalSocket},
		{"unix:@abstract", ExposureLocalSocket},
		{"unix:<unknown>", ExposureLocalSocket},
		{UnboundListenTarget, ExposureUnknown},
		{"", ExposureUnknown},
		{"example.com:80", ExposureUnknown},
		{"127.0.0.1", ExposureUnknown},
	}
	for _, tc := range tests {
		if got := ClassifyBindTarget(tc.target); got != tc.want {
			t.Errorf("ClassifyBindTarget(%q) = %q, want %q", tc.target, got, tc.want)
		}
	}
}

func TestListenerActionTypes(t *testing.T) {
	for _, at := range []ActionType{NetBind, NetListen, NetUnixConnect} {
		if !at.IsValid() {
			t.Errorf("%s must be a valid ground truth action type", at)
		}
		if at.IsClaimable() {
			t.Errorf("%s must not be claimable by a trajectory", at)
		}
	}
	for _, at := range []ActionType{FileOpen, FileRead, FileWrite, FileClose, FileRename, FileDelete,
		NetRequest, NetDNS, NetConnect, ProcessExec, ProcessExit, GitCommit} {
		if !at.IsClaimable() {
			t.Errorf("%s was claimable before listeners existed and must stay so", at)
		}
	}
	if ActionType("bogus").IsClaimable() {
		t.Error("an invalid action type must not be claimable")
	}
}

func TestListenerEventsAreValidGroundTruthButInvalidClaims(t *testing.T) {
	ts := time.Now()
	for _, at := range []ActionType{NetBind, NetListen, NetUnixConnect} {
		ev := GroundTruthEvent{Timestamp: ts, ActionType: at, Target: "127.0.0.1:80"}
		if err := ev.Validate(); err != nil {
			t.Errorf("ground truth %s rejected: %v", at, err)
		}
		entry := TrajectoryEntry{Timestamp: ts, ActionType: at, Target: "127.0.0.1:80"}
		if err := entry.Validate(); err == nil {
			t.Errorf("trajectory entry %s accepted, but listeners cannot be claimed", at)
		}
	}
}
