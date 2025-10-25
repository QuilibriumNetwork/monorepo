package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

type GRPCMessageLimitsConfig struct {
	MaxRecvMsgSize int `yaml:"maxRecvMsgSize"`
	MaxSendMsgSize int `yaml:"maxSendMsgSize"`
}

// WithDefaults returns a copy of the GRPCMessageLimitsConfig with any missing fields set to
// their default values.
func (c GRPCMessageLimitsConfig) WithDefaults(recv, send int) GRPCMessageLimitsConfig {
	cpy := c
	if cpy.MaxRecvMsgSize == 0 {
		cpy.MaxRecvMsgSize = recv
	}
	if cpy.MaxSendMsgSize == 0 {
		cpy.MaxSendMsgSize = send
	}
	return cpy
}

type Config struct {
	Alias               *AliasConfig  `yaml:"alias"`
	Key                 *KeyConfig    `yaml:"key"`
	P2P                 *P2PConfig    `yaml:"p2p"`
	Engine              *EngineConfig `yaml:"engine"`
	DB                  *DBConfig     `yaml:"db"`
	Logger              *LogConfig    `yaml:"logger"`
	ListenGRPCMultiaddr string        `yaml:"listenGrpcMultiaddr"`
	ListenRestMultiaddr string        `yaml:"listenRESTMultiaddr"`
	LogFile             string        `yaml:"logFile"`
}

// WithDefaults returns a copy of the config with default values filled in.
func (c Config) WithDefaults(configPath string) Config {
	cpy := c
	if cpy.Alias == nil {
		cpy.Alias = &AliasConfig{}
	}
	alias := cpy.Alias.WithDefaults(configPath)
	cpy.Alias = &alias
	db := cpy.DB.WithDefaults()
	cpy.DB = &db
	p2p := cpy.P2P.WithDefaults()
	cpy.P2P = &p2p
	engine := cpy.Engine.WithDefaults()
	cpy.Engine = &engine
	return cpy
}

func NewConfig(configPath string) (*Config, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	d := yaml.NewDecoder(file)
	config := &Config{}

	if err := d.Decode(&config); err != nil {
		return nil, err
	}

	return config, nil
}

var BootstrapPeers = []string{
	"/dns/bootstrap.quilibrium.com/udp/8336/quic-v1/p2p/Qme3g6rJWuz8HVXxpDb7aV2hiFq8bZJNqxMmwzmASzfq1M",
	"/dns/quecifer.quilibrium.com/udp/8336/quic-v1/p2p/QmdWF9bGTH5mwJXkxrG859HA5r34MxXtMSTuEikSMDSESv",
	"/dns/quagmire.quilibrium.com/udp/8336/quic-v1/p2p/QmaQ9KAaKtqXhYSQ5ARQNnn8B8474cWGvvD6PgJ4gAtMrx",
	// "/ip4/204.186.74.46/udp/8316/quic-v1/p2p/QmeqBjm3iX7sdTieyto1gys5ruQrQNPKfaTGcVQQWJPYDV",
	"/ip4/65.109.17.13/udp/8336/quic-v1/p2p/Qmc35n99eojSvW3PkbfBczJoSX92WmnnKh3Fg114ok3oo4",
	"/ip4/65.108.194.84/udp/8336/quic-v1/p2p/QmP8C7g9ZRiWzhqN2AgFu5onS6HwHzR6Vv1TCHxAhnCSnq",
	"/ip4/15.204.100.222/udp/8336/quic-v1/p2p/Qmef3Z3RvGg49ZpDPcf2shWtJNgPJNpXrowjUcfz23YQ3V",
	// "/ip4/69.197.174.35/udp/8336/quic-v1/p2p/QmeprCaZKiymofPJgnp2ANR3F4pRus9PHHaxnJDh1Jwr1p",
	// "/ip4/70.36.102.32/udp/8336/quic-v1/p2p/QmYriGRXCUiwFodqSoS4GgEcD7UVyxXPeCgQKmYne3iLSF",
	// "/ip4/204.12.220.2/udp/8336/quic-v1/p2p/QmRw5Tw4p5v2vLPvVSAkQEiRPQGnWk9HM4xiSvgxF82CCw",
	// "/ip4/209.159.149.14/udp/8336/quic-v1/p2p/Qmcq4Lmw45tbodvdRWZ8iGgy3rUcR3dikHTj1fBXP8VJqv",
	// "/ip4/148.251.9.90/udp/8336/quic-v1/p2p/QmRpKmQ1W83s6moBFpG6D6nrttkqdQSbdCJpvfxDVGcs38",
	// "/ip4/35.232.113.144/udp/8336/quic-v1/p2p/QmWxkBc7a17ZsLHhszLyTvKsoHMKvKae2XwfQXymiU66md",
	// "/ip4/34.87.85.78/udp/8336/quic-v1/p2p/QmTGguT5XhtvZZwTLnNQTN8Bg9eUm1THWEneXXHGhMDPrz",
	// "/ip4/34.81.199.27/udp/8336/quic-v1/p2p/QmTMMKpzCKJCwrnUzNu6tNj4P1nL7hVqz251245wsVpGNg",
	// "/ip4/34.143.255.235/udp/8336/quic-v1/p2p/QmeifsP6Kvq8A3yabQs6CBg7prSpDSqdee8P2BDQm9EpP8",
	// "/ip4/34.34.125.238/udp/8336/quic-v1/p2p/QmZdSyBJLm9UiDaPZ4XDkgRGXUwPcHJCmKoH6fS9Qjyko4",
	// "/ip4/34.80.245.52/udp/8336/quic-v1/p2p/QmNmbqobt82Vre5JxUGVNGEWn2HsztQQ1xfeg6mx7X5u3f",
	// "/dns/bravo-1.qcommander.sh/udp/8336/quic-v1/p2p/QmURj4qEB9vNdCCKzSMq4ESEgz13nJrqazgMdGi2DBSeeC",
	// "/ip4/109.199.100.108/udp/8336/quic-v1/p2p/Qma9fgugQc17MDu4YRSvnhfhVre6AYZ3nZdW8dSUYbsWvm",
	// "/ip4/47.251.49.193/udp/8336/quic-v1/p2p/QmP6ADPmMCsB8y82oFbrKTrwYWXt1CTMJ3jGNDXRHyYJgR",
	// "/ip4/138.201.203.208/udp/8336/quic-v1/p2p/QmbNhSTd4Y64ZCbV2gAXYR4ZFDdfRBMfrgWsNg99JHxsJo",
	// "/ip4/148.251.9.90/udp/8336/quic-v1/p2p/QmRpKmQ1W83s6moBFpG6D6nrttkqdQSbdCJpvfxDVGcs38",
	// "/ip4/15.235.211.121/udp/8336/quic-v1/p2p/QmZHNLUSAFCkTwHiEE3vWay3wsus5fWYsNLFTFU6tPCmNR",
	// "/ip4/63.141.228.58/udp/8336/quic-v1/p2p/QmezARggdWKa1sw3LqE3LfZwVvtuCpXpK8WVo8EEdfakJV",
	// purged peers (keep your node online to return to this list)
	// "/ip4/204.186.74.47/udp/8317/quic-v1/p2p/Qmd233pLUDvcDW3ama27usfbG1HxKNh1V9dmWVW1SXp1pd",
	// "/ip4/186.233.184.181/udp/8336/quic-v1/p2p/QmW6QDvKuYqJYYMP5tMZSp12X3nexywK28tZNgqtqNpEDL",
	// "/dns/quil.zanshindojo.org/udp/8336/quic-v1/p2p/QmXbbmtS5D12rEc4HWiHWr6e83SCE4jeThPP4VJpAQPvXq",
	// "/ip4/144.76.104.93/udp/8336/quic-v1/p2p/QmZejZ8DBGQ6foX9recW73GA6TqL6hCMX9ETWWW1Fb8xtx",
	// "/ip4/207.246.81.38/udp/8336/quic-v1/p2p/QmPBYgDy7snHon7PAn8nv1shApQBQz1iHb2sBBS8QSgQwW",
	// "/dns/abyssia.fr/udp/8336/quic-v1/p2p/QmS7C1UhN8nvzLJgFFf1uspMRrXjJqThHNN6AyEXp6oVUB",
	// "/ip4/51.15.18.247/udp/8336/quic-v1/p2p/QmYVaHXdFmHFeTa6oPixgjMVag6Ex7gLjE559ejJddwqzu",
	// "/ip4/35.232.113.144/udp/8336/quic-v1/p2p/QmWxkBc7a17ZsLHhszLyTvKsoHMKvKae2XwfQXymiU66md",
	// "/ip4/34.87.85.78/udp/8336/quic-v1/p2p/QmTGguT5XhtvZZwTLnNQTN8Bg9eUm1THWEneXXHGhMDPrz",
	// "/ip4/34.81.199.27/udp/8336/quic-v1/p2p/QmTMMKpzCKJCwrnUzNu6tNj4P1nL7hVqz251245wsVpGNg",
	// "/ip4/34.143.255.235/udp/8336/quic-v1/p2p/QmeifsP6Kvq8A3yabQs6CBg7prSpDSqdee8P2BDQm9EpP8",
	// "/ip4/34.34.125.238/udp/8336/quic-v1/p2p/QmZdSyBJLm9UiDaPZ4XDkgRGXUwPcHJCmKoH6fS9Qjyko4",
	// "/ip4/34.80.245.52/udp/8336/quic-v1/p2p/QmNmbqobt82Vre5JxUGVNGEWn2HsztQQ1xfeg6mx7X5u3f",
	// "/dns/quil.dfcnodes.eu/udp/8336/quic-v1/p2p/QmQaFmbYVrKSwoen5UQdaqyDq4QhXfSSLDVnYpYD4SF9tX",
}

type Signature struct {
	PublicKeyHex string `json:"PublicKeyHex"`
	SignatureHex string `json:"SignatureHex"`
}

type SignedGenesisUnlock struct {
	GenesisSeedHex string      `json:"genesisSeedHex"`
	Signatures     []Signature `json:"signatures"`
	// Until the broader primitives are in place, a beacon needs to kick this off
	Beacon []byte `json:"beacon"`
}

var Signatories = []string{
	"b1214da7f355f5a9edb7bcc23d403bdf789f070cca10db2b4cadc22f2d837afb650944853e35d5f42ef3c4105b802b144b4077d5d3253e4100",
	"de4cfe7083104bfe32f0d4082fa0200464d8b10804a811653eedda376efcad64dd222f0f0ceb0b8ae58abe830d7a7e3f3b2d79d691318daa00",
	"540237a35e124882d6b64e7bb5718273fa338e553f772b77fe90570e45303762b34131bdcb6c0b9f2cf9e393d9c7e0f546eeab0bcbbd881680",
	"fbe4166e37f93f90d2ebf06305315ae11b37e501d09596f8bde11ba9d343034fbca80f252205aa2f582a512a72ad293df371baa582da072900",
	"4160572e493e1bf15c44e055b11bf75230c76c7d2c67b48066770ab03dfd5ed34c97b9a431ec18578c83a0df9250b8362c38068650e8b01400",
	"45170b626884b85d61ae109f2aa9b0e1ecc18b181508431ea6308f3869f2adae49da9799a0a594eaa4ef3ad492518fb1729decd44169d40d00",
	"92cd8ee5362f3ae274a75ab9471024dbc144bff441ed8af7d19750ac512ff51e40e7f7b01e4f96b6345dd58878565948c3eb52c53f250b5080",
	"001a4cbfce5d9aeb7e20665b0d236721b228a32f0baee62ffa77f45b82ecaf577e8a38b7ef91fcf7d2d2d2b504f085461398d30b24abb1d700",
	"65b835071731c6e785bb2d107c7d85d8a537d79c435c3f42bb2f87027f93f858d7b37c598cef267a5db46e345f7a6f81969b465686657d1e00",
	"b6df0ebab6ea20cc2eb718db5873c07bb50cf239a16bb6306bbe0f24280664f99f732c4049b8eda1226067e70ffb81958834d486942a122100",
	"3e087771c36098cb2d371711fd882d309b4caebbd06ded3077a975231344f027ad31c7069e76ba5070451d8eb5abf29bfeb34fcdf9ba906480",
	"57be2861faf0fffcbfd122c85c77010dce8f213030905781b85b6f345d912c7b5ace17797d9810899dfb8d13e7c8369595740725ab3dd5bd00",
	"61628beef8f6964466fd078d6a2b90a397ab0777a14b9728227fd19f36752f9451b1a8d780740a0b9a8ce3df5f89ca7b9ff17de9274a270980",
	"9ab76d775487c85c8e5aa0c5b3f961772967899a14644651031ae5f98ac197bee3f8880492c4fdba268716fc4b7c38ffcac370b663ac10b600",
	"c0d2d47d6309572a055abf593de26a8c980be04df9672ed40939f93b51806be53f6e58f330ff348592350783d24109fa7db8bf7e61c9a8b780",
	"6e2872f73c4868c4286bef7bfe2f5479a41c42f4e07505efa4883c7950c740252e0eea78eef10c584b19b1dcda01f7767d3135d07c33244100",
	"0ca6f5a9d7f86c1111be5edf31e26979918aa4fa3daae6de1120e05c2a09bdb8d2feeb084286a3347e06ced25530358cbc74c204d2a1753a00",
}

var unlock *SignedGenesisUnlock

func DownloadAndVerifyGenesis(network uint) (*SignedGenesisUnlock, error) {
	if network != 0 {
		unlock = &SignedGenesisUnlock{
			GenesisSeedHex: "726573697374206d7563682c206f626579206c6974746c657c00000000000000000000000D",
			Beacon: []byte{
				0x58, 0xef, 0xd9, 0x7e, 0xdd, 0x0e, 0xb6, 0x2f,
				0x51, 0xc7, 0x5d, 0x00, 0x29, 0x12, 0x45, 0x49,
				0x2e, 0x2f, 0xee, 0x17, 0x24, 0xf4, 0x76, 0x0b,
				0xe6, 0x18, 0x82, 0xab, 0xca, 0x7f, 0xc8, 0x3a,
				0xbd, 0x1a, 0x9e, 0x01, 0x71, 0xb2, 0xe0, 0x8c,
				0x35, 0xa0, 0x42, 0xd0, 0x91, 0x32, 0xb0, 0x42,
				0xda, 0xee, 0x71, 0xf5, 0xe3, 0x73, 0x93, 0x4e,
				0x80,
			},
		}
	} else {
		// From https://releases.quilibrium.com/genesisunlock, skip a download:
		beacon, _ := base64.StdEncoding.DecodeString("ImqaBAzHM61pHODoywHu2a6FIOqoXKY/RECZuOXjDfds8DBxtA0g+4hCfOgwiti2TpOF8AH7xH0A")
		unlock = &SignedGenesisUnlock{
			GenesisSeedHex: "726573697374206d7563682c206f626579206c6974746c657c083fb0a4274b1f70e9aa2b3f",
			Signatures: []Signature{
				{
					PublicKeyHex: "b1214da7f355f5a9edb7bcc23d403bdf789f070cca10db2b4cadc22f2d837afb650944853e35d5f42ef3c4105b802b144b4077d5d3253e4100",
					SignatureHex: "5176d46e7974cb0d37eb16864fa01ed4d10222ffd38009e451a6339af0ae4938d95dad7af5db7ea9a3bc818cf4dee8e20f9a3be6717d45aa80c0b8bf9783bc5129a7efb0cd900b2a56d84f16d2c531e16a4c4456a37ebed68b95dff3d5b910705aa3963989a92e8908d8eb58622d47bb0c00",
				},
				{
					PublicKeyHex: "de4cfe7083104bfe32f0d4082fa0200464d8b10804a811653eedda376efcad64dd222f0f0ceb0b8ae58abe830d7a7e3f3b2d79d691318daa00",
					SignatureHex: "6f6fb897e54787d716697b54bb18eab857857114d30ca3abe7949d1d1502662a4b181942a207d7ebb144ebd56b0eb83b7860eddf85d51bcd0065d1429006a5840dad464d21d0ac0293bec6ec0ea9f7b38c48e9979febaa36e51101f8a263d1e7666d3cc23746626168d2ad2c817b36f00a00",
				},
				{
					PublicKeyHex: "540237a35e124882d6b64e7bb5718273fa338e553f772b77fe90570e45303762b34131bdcb6c0b9f2cf9e393d9c7e0f546eeab0bcbbd881680",
					SignatureHex: "2ef74fb5222ca8053543b6f62aa89a728fb316c17154c191a27fc50d9923ca55bf469c32134df667a142e28ef563205e72fcfcc0afed3ff50032975bee3f6f2b8f14b90a3693d065075880f0e42755de2828882f5245840edb71083fc8620f041ed44da8515b03360ea6d78715c189f71300",
				},
				{
					PublicKeyHex: "fbe4166e37f93f90d2ebf06305315ae11b37e501d09596f8bde11ba9d343034fbca80f252205aa2f582a512a72ad293df371baa582da072900",
					SignatureHex: "15b25055d570d8a6a1caab8e266995609fc7489045f216871a37201c85515c341c1dbf3f0537ff9436579858ee38c4741dce9e00b4c1ddf180cb592cc73ef6ba6e9374d8a8937fac84ad76a66b528164db9a8de48a11a15557f296f075f729617afe9ca17552f1a8f6dd2c1bb151f2930e00",
				},
				{
					PublicKeyHex: "45170b626884b85d61ae109f2aa9b0e1ecc18b181508431ea6308f3869f2adae49da9799a0a594eaa4ef3ad492518fb1729decd44169d40d00",
					SignatureHex: "4af69e871617eee5ba8b51d73190500bc064ec77e7e396e4d8bca1942dfb538007b1f1ac65787d57f3406e54279d3d360f465723eaf58a8e002cfd54fe78c2c8799cb71a37ea13debd32b868005ff61eea9946b063fa25407929dc445e99b58786e3fe01749208e2a2e367640d9a66130100",
				},
				{
					PublicKeyHex: "001a4cbfce5d9aeb7e20665b0d236721b228a32f0baee62ffa77f45b82ecaf577e8a38b7ef91fcf7d2d2d2b504f085461398d30b24abb1d700",
					SignatureHex: "966f12f5b59f9ac18e15608f638938c137017c9a68f5419de8560f6aedffd454b0dbd6326719a37c84b1e56795933f1584e156145f8814970000554d97e98156c1489b95a1cd196391f71f13d4958eaa66054399c710fe32c4e6cb3214c1f2126f3d44a3402247209cf32bf17b5806d63700",
				},
				{
					PublicKeyHex: "61628beef8f6964466fd078d6a2b90a397ab0777a14b9728227fd19f36752f9451b1a8d780740a0b9a8ce3df5f89ca7b9ff17de9274a270980",
					SignatureHex: "9521933c79b269d33f38ca45f65f02555ae2126e0c378f40ccbf6edc16680035098104caf34a91733043297b44870a739af2ce23a035ffa080b394d438eb781d69167966b7aec1ba2194cda276dfdcf25158d4795f863d779a28c3fd7858ba3b9d3af6c69d91e5609c1b3a28101697500f00",
				},
				{
					PublicKeyHex: "81d63a45f068629f568de812f18be5807bfe828a830097f09cf02330d6acd35e3607401df3fda08b03b68ea6e68afd506b23506b11e87a0f80",
					SignatureHex: "3ebba8c10d2e188ce8e7138d2189dac51a3854c9706849f28c7f60a264951cc5b88534793e5a25b540bb2cb736da5c0b97040ed904d79afe8061e4ad334b16b89a3e29c1c26f6062fc6db146a00f9b7da76ee237004f60bca6e32f452d9074b4c07402092a62cb2596c2eab96d80454c0000",
				},
				{
					PublicKeyHex: "6e2872f73c4868c4286bef7bfe2f5479a41c42f4e07505efa4883c7950c740252e0eea78eef10c584b19b1dcda01f7767d3135d07c33244100",
					SignatureHex: "5701f5cd907a105d0421d2d6d49b147410211e297ef1bc7b8040ec96c742d1b628523cda378ebb57e37bf6a9b6d23bf196a75dc1c461d5b5809be734030c41e577854641b103fe394524439e2c538458bdd4b5490176bf35cac03eb90dfd9b54ff87e46f0da4b7fd2057394922c448eb1c00",
				},
			},
			Beacon: beacon,
		}
	}

	return unlock, nil
}

func GetGenesis() *SignedGenesisUnlock {
	return unlock
}

var StasisSeed = "737461736973"

func LoadConfig(configPath string, proverKey string, skipGenesisCheck bool) (
	*Config,
	error,
) {
	info, err := os.Stat(configPath)
	if os.IsNotExist(err) {
		fmt.Println("Creating config directory:", configPath)
		if err = os.Mkdir(configPath, fs.FileMode(0700)); err != nil {
			log.Panic("Failed to create config directory", err)
		}
	} else {
		if err != nil {
			log.Panic("Failed to stat config directory", err)
		}

		if !info.IsDir() {
			log.Panic("Config path is not a directory:", configPath)
		}
	}

	file, err := os.Open(filepath.Join(configPath, "config.yml"))
	saveDefaults := false
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			saveDefaults = true
		} else {
			return nil, err
		}
	}

	genesisSeed := StasisSeed

	if !skipGenesisCheck {
		output, err := DownloadAndVerifyGenesis(0)
		if err == nil {
			genesisSeed = output.GenesisSeedHex
		}
	}

	config := &Config{
		DB: &DBConfig{
			Path:             configPath + "/store",
			WorkerPathPrefix: configPath + "/worker-store/%d",
		},
		Key: &KeyConfig{
			KeyStore: KeyManagerTypeFile,
			KeyStoreFile: &KeyStoreFileConfig{
				Path: filepath.Join(configPath, "keys.yml"),
			},
		},
		P2P: &P2PConfig{
			ListenMultiaddr: "/ip4/0.0.0.0/udp/8336/quic-v1",
			BootstrapPeers:  BootstrapPeers,
			PeerPrivKey:     "",
			Network:         0,
		},
		Engine: &EngineConfig{
			ProvingKeyId:         "default-proving-key",
			Filter:               "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			GenesisSeed:          genesisSeed,
			MaxFrames:            -1,
			PendingCommitWorkers: 4,
		},
	}

	if saveDefaults {
		fmt.Println("Generating default config...")
		fmt.Println("Generating random host key...")
		privkey, _, err := crypto.GenerateEd448Key(rand.Reader)
		if err != nil {
			log.Panic("Failed to generate host key", err)
		}

		hostKey, err := privkey.Raw()
		if err != nil {
			log.Panic("Failed to get raw host key", err)
		}

		config.P2P.PeerPrivKey = hex.EncodeToString(hostKey)

		fmt.Println("Generating keystore key...")
		keystoreKey := make([]byte, 32)
		if _, err := rand.Read(keystoreKey); err != nil {
			log.Panic("Failed to generate keystore key", err)
		}

		config.Key.KeyStoreFile.EncryptionKey = hex.EncodeToString(keystoreKey)

		if multiAddr := os.Getenv("DEFAULT_LISTEN_GRPC_MULTIADDR"); multiAddr != "" {
			config.ListenGRPCMultiaddr = multiAddr
			config.ListenRestMultiaddr = os.Getenv("DEFAULT_LISTEN_REST_MULTIADDR")
		}

		if multiAddr := os.Getenv("DEFAULT_STATS_MULTIADDR"); multiAddr != "" {
			config.Engine.StatsMultiaddr = multiAddr
		}

		fmt.Println("Saving config to", configPath)
		if err = SaveConfig(configPath, config); err != nil {
			log.Panic("Failed to save config", err)
		}

		keyfile, err := os.OpenFile(
			filepath.Join(configPath, "keys.yml"),
			os.O_CREATE|os.O_RDWR,
			fs.FileMode(0600),
		)
		if err != nil {
			log.Panic("Failed to open key file", err)
		}

		if proverKey != "" {
			provingKey, err := hex.DecodeString(proverKey)
			if err != nil {
				log.Panic("Failed to decode proving key", err)
			}

			iv := [12]byte{}
			rand.Read(iv[:])
			aesCipher, err := aes.NewCipher(keystoreKey)
			if err != nil {
				return nil, errors.Wrap(err, "could not construct cipher")
			}

			gcm, err := cipher.NewGCM(aesCipher)
			if err != nil {
				return nil, errors.Wrap(err, "could not construct block")
			}

			ciphertext := gcm.Seal(nil, iv[:], provingKey, nil)
			ciphertext = append(append([]byte{}, iv[:]...), ciphertext...)

			provingPubKey := ed448.PrivateKey(provingKey).Public().(ed448.PublicKey)

			keyfile.Write([]byte(
				"default-proving-key:\n  id: default-proving-key\n" +
					"  type: 0\n  privateKey: " + hex.EncodeToString(ciphertext) + "\n" +
					"  publicKey: " + hex.EncodeToString(provingPubKey) + "\n"))
		} else {
			keyfile.Write([]byte("null:\n"))
		}

		keyfile.Close()

		if file, err = os.Open(
			filepath.Join(configPath, "config.yml"),
		); err != nil {
			log.Panic("Failed to open config file", err)
		}
	}

	defer file.Close()
	d := yaml.NewDecoder(file)
	if err := d.Decode(&config); err != nil {
		return nil, err
	}

	if config.Engine.GenesisSeed == "00" {
		config.Engine.GenesisSeed = genesisSeed
	}

	// upgrade quic string to quic-v1
	if strings.HasSuffix(config.P2P.ListenMultiaddr, "/quic") {
		config.P2P.ListenMultiaddr += "-v1"
	}

	// Slight trick here to get people on the latest bootstrap list –
	// if it's empty, always use latest, if it has the Q bootstrap node, always
	// use latest.
	if len(config.P2P.BootstrapPeers) == 0 ||
		config.P2P.BootstrapPeers[0][:30] == "/dns/bootstrap.quilibrium.com/" {
		config.P2P.BootstrapPeers = BootstrapPeers
	} else {
		peers := make([]string, len(config.P2P.BootstrapPeers))
		for i, p := range config.P2P.BootstrapPeers {
			// upgrade quic strings to quic-v1
			peers[i] = strings.Replace(p, "/quic/", "/quic-v1/", 1)
		}
		config.P2P.BootstrapPeers = peers
	}

	withDefaults := config.WithDefaults(configPath)
	return &withDefaults, nil
}

func SaveConfig(configPath string, config *Config) error {
	file, err := os.OpenFile(
		filepath.Join(configPath, "config.yml"),
		os.O_CREATE|os.O_RDWR,
		os.FileMode(0600),
	)
	if err != nil {
		return err
	}

	defer file.Close()

	d := yaml.NewEncoder(file)

	if err := d.Encode(config); err != nil {
		return err
	}

	return nil
}

type setter struct {
	dst    *string
	dstver *string
	value  string
	ver    string
}

func (s setter) String() string { return "" }
func (s setter) Set(_ string) error {
	*s.dst = s.value
	*s.dstver = s.ver
	return nil
}
func (s setter) IsBoolFlag() bool { return true }

func Flags(blockchar **string, ver **string) {
	flag.Var(
		setter{
			*blockchar,
			*ver,
			"\U0001F1EB\U0001F1F7 ",
			"\U00000047\U0000006F\U0000006F\U00000062\U00000079",
		},
		"\U00000067\U0000006F\U0000006F\U00000062\U00000079",
		"",
	)
	flag.Var(
		setter{
			*blockchar,
			*ver,
			"\U0001F33B",
			"\U00000042\U0000006C\U0000006F\U0000006F\U0000006D",
		},
		"\U00000062\U0000006C\U0000006F\U0000006F\U0000006D",
		"",
	)
	flag.Var(
		setter{
			*blockchar,
			*ver,
			"\U0001F409",
			"\U000054EA\U00005412",
		},
		"\U000054EA\U00005412",
		"",
	)
}

func PrintLogo(char string) {
	schar := " "
	if char != "█" {
		schar = "  "
	}
	logo := strings.ReplaceAll(
		strings.ReplaceAll(
			"████████████████████████████████████████████████████████████████████████████████\n"+
				"████████████████████████████████████████████████████████████████████████████████\n"+
				"██████████████████████████████                    ██████████████████████████████\n"+
				"█████████████████████████                              █████████████████████████\n"+
				"█████████████████████                                      █████████████████████\n"+
				"██████████████████                                            ██████████████████\n"+
				"████████████████                     ██████                     ████████████████\n"+
				"██████████████                ████████████████████                ██████████████\n"+
				"█████████████             ████████████████████████████              ████████████\n"+
				"███████████            ██████████████████████████████████            ███████████\n"+
				"██████████           ██████████████████████████████████████           ██████████\n"+
				"█████████          ██████████████████████████████████████████          █████████\n"+
				"████████          ████████████████████████████████████████████          ████████\n"+
				"███████          ████████████████████      ████████████████████          ███████\n"+
				"██████          ███████████████████          ███████████████████          ██████\n"+
				"█████          ███████████████████            ███████████████████          █████\n"+
				"█████         ████████████████████            ████████████████████         █████\n"+
				"████         █████████████████████            █████████████████████         ████\n"+
				"████         ██████████████████████          ██████████████████████         ████\n"+
				"████        █████████████████████████      █████████████████████████        ████\n"+
				"████        ████████████████████████████████████████████████████████        ████\n"+
				"████        ████████████████████████████████████████████████████████        ████\n"+
				"████        ████████████████████  ████████████  ████████████████████        ████\n"+
				"████        ██████████████████                   ███████████████████        ████\n"+
				"████         ████████████████                      ████████████████         ████\n"+
				"████         ██████████████            ██            ██████████████         ████\n"+
				"█████        ████████████            ██████            ████████████        █████\n"+
				"█████         █████████            ██████████            █████████         █████\n"+
				"██████         ███████           █████████████             ███████        ██████\n"+
				"██████          ████████       █████████████████            ████████      ██████\n"+
				"███████          █████████   █████████████████████            ████████   ███████\n"+
				"████████           █████████████████████████████████            ████████████████\n"+
				"█████████           ██████████████████████████████████            ██████████████\n"+
				"██████████            ██████████████████████████████████           █████████████\n"+
				"████████████             ████████████████████████████████            ███████████\n"+
				"█████████████               ███████████████████████████████            █████████\n"+
				"███████████████                 ████████████████    █████████            ███████\n"+
				"█████████████████                                     █████████            █████\n"+
				"████████████████████                                    █████████         ██████\n"+
				"███████████████████████                                  ██████████     ████████\n"+
				"███████████████████████████                          ███████████████  ██████████\n"+
				"█████████████████████████████████              █████████████████████████████████\n"+
				"████████████████████████████████████████████████████████████████████████████████\n"+
				"████████████████████████████████████████████████████████████████████████████████",
			" ",
			string(schar),
		),
		"█",
		string(char),
	)
	fmt.Println(logo)
}

func PrintVersion(network uint8, char string, ver string) {
	schar := " "
	if char != "█" {
		schar = "   "
	}

	patch := GetPatchNumber()
	patchString := ""
	if patch != 0x00 {
		patchString = fmt.Sprintf("-p%d", patch)
	}
	if network != 0 {
		patchString = fmt.Sprintf("-b%d", GetRCNumber())
	}
	fmt.Println(" ")
	fmt.Println(strings.ReplaceAll(
		"                     ",
		" ",
		schar,
	) + "  Quilibrium Node - v" + GetVersionString() + patchString + " – " + ver)
}
