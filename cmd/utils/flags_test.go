// Copyright 2019 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

// Package utils contains internal helper functions for go-ethereum commands.
package utils

import (
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/nodekey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/urfave/cli.v1"
)

func TestAuthorizationList(t *testing.T) {
	value := "1=" + common.HexToHash("0xfa").Hex() + ",2=" + common.HexToHash("0x12").Hex()
	result := map[uint64]common.Hash{
		1: common.HexToHash("0xfa"),
		2: common.HexToHash("0x12"),
	}

	arbitraryNodeConfig := &eth.Config{}
	fs := &flag.FlagSet{}
	fs.String(AuthorizationListFlag.Name, value, "")
	arbitraryCLIContext := cli.NewContext(nil, fs, nil)
	arbitraryCLIContext.GlobalSet(AuthorizationListFlag.Name, value)
	setAuthorizationList(arbitraryCLIContext, arbitraryNodeConfig)
	assert.Equal(t, result, arbitraryNodeConfig.AuthorizationList)

	fs = &flag.FlagSet{}
	fs.String(AuthorizationListFlag.Name, value, "")
	arbitraryCLIContext = cli.NewContext(nil, fs, nil)
	arbitraryCLIContext.GlobalSet(DeprecatedAuthorizationListFlag.Name, value) // old wlist flag
	setAuthorizationList(arbitraryCLIContext, arbitraryNodeConfig)
	assert.Equal(t, result, arbitraryNodeConfig.AuthorizationList)
}

func TestSetPlugins_whenPluginsNotEnabled(t *testing.T) {
	arbitraryNodeConfig := &node.Config{}
	arbitraryCLIContext := cli.NewContext(nil, &flag.FlagSet{}, nil)

	assert.NoError(t, SetPlugins(arbitraryCLIContext, arbitraryNodeConfig))

	assert.Nil(t, arbitraryNodeConfig.Plugins)
}

func TestSetPlugins_whenInvalidFlagsCombination(t *testing.T) {
	arbitraryNodeConfig := &node.Config{}
	fs := &flag.FlagSet{}
	fs.String(PluginSettingsFlag.Name, "", "")
	fs.Bool(PluginSkipVerifyFlag.Name, true, "")
	fs.Bool(PluginLocalVerifyFlag.Name, true, "")
	fs.String(PluginPublicKeyFlag.Name, "", "")
	arbitraryCLIContext := cli.NewContext(nil, fs, nil)
	assert.NoError(t, arbitraryCLIContext.GlobalSet(PluginSettingsFlag.Name, "arbitrary value"))

	verifyErrorMessage(t, arbitraryCLIContext, arbitraryNodeConfig, "only --plugins.skipverify or --plugins.localverify must be set")

	assert.NoError(t, arbitraryCLIContext.GlobalSet(PluginSkipVerifyFlag.Name, "false"))
	assert.NoError(t, arbitraryCLIContext.GlobalSet(PluginLocalVerifyFlag.Name, "false"))
	assert.NoError(t, arbitraryCLIContext.GlobalSet(PluginPublicKeyFlag.Name, "arbitrary value"))

	verifyErrorMessage(t, arbitraryCLIContext, arbitraryNodeConfig, "--plugins.localverify is required for setting --plugins.publickey")
}

func TestSetPlugins_whenInvalidPluginSettingsURL(t *testing.T) {
	arbitraryNodeConfig := &node.Config{}
	fs := &flag.FlagSet{}
	fs.String(PluginSettingsFlag.Name, "", "")
	arbitraryCLIContext := cli.NewContext(nil, fs, nil)
	assert.NoError(t, arbitraryCLIContext.GlobalSet(PluginSettingsFlag.Name, "arbitrary value"))

	verifyErrorMessage(t, arbitraryCLIContext, arbitraryNodeConfig, "plugins: unable to create reader due to unsupported scheme ")
}

func TestSetImmutabilityThreshold(t *testing.T) {
	fs := &flag.FlagSet{}
	fs.Int(QuorumImmutabilityThreshold.Name, 0, "")
	arbitraryCLIContext := cli.NewContext(nil, fs, nil)
	assert.NoError(t, arbitraryCLIContext.GlobalSet(QuorumImmutabilityThreshold.Name, strconv.Itoa(100000)))
	assert.True(t, arbitraryCLIContext.GlobalIsSet(QuorumImmutabilityThreshold.Name), "immutability threshold flag not set")
	assert.Equal(t, 100000, arbitraryCLIContext.GlobalInt(QuorumImmutabilityThreshold.Name), "immutability threshold value not set")
}

func TestSetPlugins_whenTypical(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "q-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()
	arbitraryJSONFile := path.Join(tmpDir, "arbitary.json")
	if err := os.WriteFile(arbitraryJSONFile, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	arbitraryNodeConfig := &node.Config{}
	fs := &flag.FlagSet{}
	fs.String(PluginSettingsFlag.Name, "", "")
	arbitraryCLIContext := cli.NewContext(nil, fs, nil)
	assert.NoError(t, arbitraryCLIContext.GlobalSet(PluginSettingsFlag.Name, "file://"+arbitraryJSONFile))

	assert.NoError(t, SetPlugins(arbitraryCLIContext, arbitraryNodeConfig))

	assert.NotNil(t, arbitraryNodeConfig.Plugins)
}

func verifyErrorMessage(t *testing.T, ctx *cli.Context, cfg *node.Config, expectedMsg string) {
	err := SetPlugins(ctx, cfg)
	assert.EqualError(t, err, expectedMsg)
}

func Test_SplitTagsFlag(t *testing.T) {
	tests := []struct {
		name string
		args string
		want map[string]string
	}{
		{
			"2 tags case",
			"host=localhost,bzzkey=123",
			map[string]string{
				"host":   "localhost",
				"bzzkey": "123",
			},
		},
		{
			"1 tag case",
			"host=localhost123",
			map[string]string{
				"host": "localhost123",
			},
		},
		{
			"empty case",
			"",
			map[string]string{},
		},
		{
			"garbage",
			"smth=smthelse=123",
			map[string]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SplitTagsFlag(tt.args); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("splitTagsFlag() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestQuorumConfigFlags(t *testing.T) {
	fs := &flag.FlagSet{}
	arbitraryCLIContext := cli.NewContext(nil, fs, nil)
	arbitraryEthConfig := &eth.Config{}

	fs.Int(EVMCallTimeOutFlag.Name, 0, "")
	assert.NoError(t, arbitraryCLIContext.GlobalSet(EVMCallTimeOutFlag.Name, strconv.Itoa(12)))
	fs.Bool(MultitenancyFlag.Name, false, "")
	assert.NoError(t, arbitraryCLIContext.GlobalSet(MultitenancyFlag.Name, "true"))
	fs.Bool(QuorumEnablePrivacyMarker.Name, true, "")
	assert.NoError(t, arbitraryCLIContext.GlobalSet(QuorumEnablePrivacyMarker.Name, "true"))
	fs.Uint64(IstanbulRequestTimeoutFlag.Name, 0, "")
	assert.NoError(t, arbitraryCLIContext.GlobalSet(IstanbulRequestTimeoutFlag.Name, "23"))
	fs.Uint64(IstanbulBlockPeriodFlag.Name, 0, "")
	assert.NoError(t, arbitraryCLIContext.GlobalSet(IstanbulBlockPeriodFlag.Name, "34"))
	fs.Bool(RaftModeFlag.Name, false, "")
	assert.NoError(t, arbitraryCLIContext.GlobalSet(RaftModeFlag.Name, "true"))

	require.NoError(t, setQuorumConfig(arbitraryCLIContext, arbitraryEthConfig))

	assert.True(t, arbitraryCLIContext.GlobalIsSet(EVMCallTimeOutFlag.Name), "EVMCallTimeOutFlag not set")
	assert.True(t, arbitraryCLIContext.GlobalIsSet(MultitenancyFlag.Name), "MultitenancyFlag not set")
	assert.True(t, arbitraryCLIContext.GlobalIsSet(RaftModeFlag.Name), "RaftModeFlag not set")

	assert.Equal(t, 12*time.Second, arbitraryEthConfig.EVMCallTimeOut, "EVMCallTimeOut value is incorrect")
	assert.Equal(t, true, arbitraryEthConfig.QuorumChainConfig.MultiTenantEnabled(), "MultitenancyFlag value is incorrect")
	assert.Equal(t, true, arbitraryEthConfig.QuorumChainConfig.PrivacyMarkerEnabled(), "QuorumEnablePrivacyMarker value is incorrect")
	config := arbitraryEthConfig.Istanbul.GetConfig(nil)
	assert.Equal(t, uint64(23), config.RequestTimeout, "IstanbulRequestTimeoutFlag value is incorrect")
	assert.Equal(t, uint64(34), config.BlockPeriod, "IstanbulBlockPeriodFlag value is incorrect")
	assert.Equal(t, uint64(0), config.EmptyBlockPeriod, "IstanbulEmptyBlockPeriodFlag value is incorrect")
	assert.Equal(t, true, arbitraryEthConfig.RaftMode, "RaftModeFlag value is incorrect")
}

func TestP2PNodeKeyFromFileConfigFlags(t *testing.T) {
	fs := &flag.FlagSet{}
	arbitraryCLIContext := cli.NewContext(nil, fs, nil)

	arbitraryP2PConfig := &p2p.Config{
		NodeKey: nodekey.NodeKeyConfig{
			ConfigFile: nodekey.FileConfig{
				Hex: "68b1d06cb4054d40344d138e1b7b638e81b39a209e537b673357939ed4c70392",
			},
		},
	}
	fs.String(NodeKeyDecryption.Name, "none", "")
	assert.NoError(t, arbitraryCLIContext.GlobalSet(NodeKeyDecryption.Name, "none"))
	fs.String(NodeKeySource.Name, "file", "")
	assert.NoError(t, arbitraryCLIContext.GlobalSet(NodeKeySource.Name, "file"))

	// test that user is able to pass in private key or private key path to config toml file
	require.NoError(t, setNodeKey(arbitraryCLIContext, arbitraryP2PConfig))

	// default behavior is to set private key to nil
	arbitraryP2PConfig = &p2p.Config{}
	require.NoError(t, setNodeKey(arbitraryCLIContext, arbitraryP2PConfig))
}

func TestP2PNodeKeyFromVaultConfigFlags(t *testing.T) {
	fs := &flag.FlagSet{}
	arbitraryCLIContext := cli.NewContext(nil, fs, nil)

	arbitraryP2PConfig := &p2p.Config{
		NodeKey: nodekey.NodeKeyConfig{
			ConfigFile: nodekey.FileConfig{
				Hex: "68b1d06cb4054d40344d138e1b7b638e81b39a209e537b673357939ed4c70392",
			},
		},
	}
	fs.String(NodeKeyDecryption.Name, "none", "")
	assert.NoError(t, arbitraryCLIContext.GlobalSet(NodeKeyDecryption.Name, "none"))
	fs.String(NodeKeySource.Name, "file", "")
	assert.NoError(t, arbitraryCLIContext.GlobalSet(NodeKeySource.Name, "vault-kv"))

	// test that error is returned if vault configurations are not passed into config toml file and cli selects vault-kv as source
	require.ErrorContains(t, setNodeKey(arbitraryCLIContext, arbitraryP2PConfig), "invalid kv version configuration passed, only accepts (v1|v2)")

	arbitraryP2PConfig = &p2p.Config{
		NodeKey: nodekey.NodeKeyConfig{
			ConfigVault: nodekey.VaultConfig{
				KvVersion: "v2",
			},
		},
	}
	require.ErrorContains(t, setNodeKey(arbitraryCLIContext, arbitraryP2PConfig), "need to specify default key to retrieve data from kv store")

	arbitraryP2PConfig = &p2p.Config{
		NodeKey: nodekey.NodeKeyConfig{
			ConfigVault: nodekey.VaultConfig{
				KvVersion:  "v2",
				KvFetchKey: "nodekey",
				KvPath:     "test-user/nodekey",
				KvMount:    "kv",
			},
		},
	}
	require.ErrorContains(t, setNodeKey(arbitraryCLIContext, arbitraryP2PConfig), "need to specify vault url")

	// test fetching node key from kv store
	kvFetchKey := "nodekey"
	kvPath := "test-user/nodekey"
	privateKey := "68b1d06cb4054d40344d138e1b7b638e81b39a209e537b673357939ed4c70392"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/approle/login" {
			w.WriteHeader(http.StatusOK)
			mockResponse, _ := hex.DecodeString("7b22726571756573745f6964223a2230663230393038662d326164302d313538352d383762612d666462336332396436663537222c226c656173655f6964223a22222c2272656e657761626c65223a66616c73652c226c656173655f6475726174696f6e223a302c2264617461223a6e756c6c2c22777261705f696e666f223a6e756c6c2c227761726e696e6773223a6e756c6c2c2261757468223a7b22636c69656e745f746f6b656e223a226876622e4141414141514b4e41355f33616c4152334634736b4631445f695a6f76344759384e794c51492d4f7543372d4d77795f5438717068336f7777427756553367546d6f69575476383551764267385956355f67613870593630466957514e625a65514272545f483258467a637049784d3767707631516a79516a37464872636436794a7a7345594a554b6c76343844367a6f5138452d34446949693031635574396f5f414f574269325241544b54554271777552503847316541636f31446f733044797054594e5a6457336f744651323630703776624c71444c6d74524f67222c226163636573736f72223a22222c22706f6c6963696573223a5b2261646d696e222c2264656661756c74225d2c22746f6b656e5f706f6c6963696573223a5b2261646d696e222c2264656661756c74225d2c226d65746164617461223a7b22726f6c655f6e616d65223a2261646d696e2d726f6c65227d2c226c656173655f6475726174696f6e223a323539323030302c2272656e657761626c65223a66616c73652c22656e746974795f6964223a2262653038653864642d636263352d373239332d613631372d386131666263336338333039222c22746f6b656e5f74797065223a226261746368222c226f727068616e223a747275652c226d66615f726571756972656d656e74223a6e756c6c2c226e756d5f75736573223a307d2c226d6f756e745f74797065223a22227d0a")
			w.Write(mockResponse)
			return
		}

		if r.URL.Path == fmt.Sprintf("/v1/kv-v2/data/%s", kvPath) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf(`{"Data": {"data": {"%s": "%s"}}}`, kvFetchKey, privateKey)))
			return
		}
	}))
	arbitraryP2PConfig = &p2p.Config{
		NodeKey: nodekey.NodeKeyConfig{
			ConfigVault: nodekey.VaultConfig{
				KvVersion:   "v2",
				KvFetchKey:  kvFetchKey,
				KvPath:      kvPath,
				Url:         server.URL,
				AppRolePath: "approle",
			},
		},
	}
	require.NoError(t, setNodeKey(arbitraryCLIContext, arbitraryP2PConfig))
	require.Equal(t, hexutil.Encode(crypto.FromECDSA(arbitraryP2PConfig.PrivateKey))[2:], privateKey)
}
