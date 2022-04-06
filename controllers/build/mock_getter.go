// Code generated by MockGen. DO NOT EDIT.
// Source: getter.go

// Package build is a generated GoMock package.
package build

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	v1alpha1 "github.com/qbarrand/oot-operator/api/v1alpha1"
)

// MockGetter is a mock of Getter interface.
type MockGetter struct {
	ctrl     *gomock.Controller
	recorder *MockGetterMockRecorder
}

// MockGetterMockRecorder is the mock recorder for MockGetter.
type MockGetterMockRecorder struct {
	mock *MockGetter
}

// NewMockGetter creates a new mock instance.
func NewMockGetter(ctrl *gomock.Controller) *MockGetter {
	mock := &MockGetter{ctrl: ctrl}
	mock.recorder = &MockGetterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockGetter) EXPECT() *MockGetterMockRecorder {
	return m.recorder
}

// ImageExists mocks base method.
func (m *MockGetter) ImageExists(ctx context.Context, containerImage string, po v1alpha1.PullOptions) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ImageExists", ctx, containerImage, po)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ImageExists indicates an expected call of ImageExists.
func (mr *MockGetterMockRecorder) ImageExists(ctx, containerImage, po interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ImageExists", reflect.TypeOf((*MockGetter)(nil).ImageExists), ctx, containerImage, po)
}