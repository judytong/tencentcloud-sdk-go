package common

import (
	"sync"
	"time"

	"cloud.tencent.com/tencent-cloudprovider/component"
)

const (
	expiredDuration = 7200
)

type CredentialInterface interface {
	GetCredentialParams() map[string]string
	GetSecretKey() string
}

type Credential struct {
	SecretId  string
	SecretKey string
}

func NewCredential(secretId, secretKey string) *Credential {
	return &Credential{
		SecretId:  secretId,
		SecretKey: secretKey,
	}
}

func (c *Credential) GetCredentialParams() map[string]string {
	return map[string]string{
		"SecretId": c.SecretId,
	}
}

func (c *Credential) GetSecretKey() string {
	return c.SecretKey
}

type TokenCredential struct {
	SecretId  string
	SecretKey string
	Token     string
	expiredAt time.Time
	lock      sync.Mutex
}

func NewTokenCredential(secretId, secretKey, token string) *TokenCredential {
	return &TokenCredential{
		SecretId:  secretId,
		SecretKey: secretKey,
		Token:     token,
	}
}

func (c *TokenCredential) GetSecretKey() string {
	return c.SecretKey
}

func (c *TokenCredential) GetCredentialParams() map[string]string {
	//if need update, update token
	if time.Now().Add(expiredDuration / 2 * time.Second).After(c.expiredAt) {
		rsp, err := component.NormGetAgentCredential(
			component.NormGetAgentCredentialReq{
				Duration: expiredDuration,
			},
		)
		if err != nil {
			return map[string]string{
				"SecretId": c.SecretId,
				"Token":    c.Token,
			}
		}
		c.updateTokenCredential(rsp.Credentials.TmpSecretId, rsp.Credentials.TmpSecretKey, rsp.Credentials.Token, time.Unix(int64(rsp.ExpiredTime), 0))
	}
	return map[string]string{
		"SecretId": c.SecretId,
		"Token":    c.Token,
	}
}

func (c *TokenCredential) updateTokenCredential(secretId, secretKey, token string, expiredTime time.Time) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.SecretId = secretId
	c.SecretKey = secretKey
	c.Token = token
	c.expiredAt = expiredTime
}
