package dkim

import (
	"context"
	"fmt"
)

// MockTXTResolver is a mock implementation of TXTResolver for testing.
type MockTXTResolver struct {
	Records map[string][]string
}

// NewMockTXTResolver creates a new mock TXTResolver.
func NewMockTXTResolver() *MockTXTResolver {
	return &MockTXTResolver{
		Records: make(map[string][]string),
	}
}

// LookupTXT returns mock TXT records for the given name.
func (m *MockTXTResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if records, ok := m.Records[name]; ok {
		return records, nil
	}
	return nil, fmt.Errorf("no record found for %s", name)
}

// AddRecord adds a TXT record to the mock resolver.
func (m *MockTXTResolver) AddRecord(name, record string) {
	m.Records[name] = []string{record}
}
