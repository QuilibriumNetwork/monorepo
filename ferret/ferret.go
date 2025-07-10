package ferret

import (
	"fmt"

	"github.com/pkg/errors"
	generated "source.quilibrium.com/quilibrium/monorepo/ferret/generated/ferret"
)

//go:generate ./generate.sh

const (
	ALICE = 1
	BOB   = 2
)

type FerretOT struct {
	party     int
	ferretCOT *generated.FerretCotManager
	netio     *generated.NetIoManager
}

func NewFerretOT(
	party int,
	address string,
	port int,
	threads int,
	length uint64,
	choices []bool,
	malicious bool,
) (*FerretOT, error) {
	if threads > 1 {
		fmt.Println(
			"!!!WARNING!!! THERE BE DRAGONS. RUNNING MULTITHREADED MODE IN SOME " +
				"SITUATIONS HAS LEAD TO CRASHES AND OTHER ISSUES. IF YOU STILL WISH " +
				"TO DO THIS, YOU WILL NEED TO MANUALLY UPDATE THE BUILD AND REMOVE " +
				"THIS CHECK. DO SO AT YOUR OWN RISK",
		)
		return nil, errors.Wrap(errors.New("invalid thread count"), "new ferret ot")
	}

	var addr *string
	if address != "" {
		addrCopy := address
		addr = &addrCopy
	}

	netio := generated.CreateNetioManager(
		int32(party),
		addr,
		int32(port),
	)

	ferretCOT := generated.CreateFerretCotManager(
		int32(party),
		int32(threads),
		length,
		choices,
		netio,
		malicious,
	)

	return &FerretOT{
		party:     party,
		ferretCOT: ferretCOT,
		netio:     netio,
	}, nil
}

func (ot *FerretOT) SendCOT() error {
	if ot.party != ALICE {
		return errors.New("incorrect party")
	}

	ot.ferretCOT.SendCot()

	return nil
}

func (ot *FerretOT) RecvCOT() error {
	if ot.party != BOB {
		return errors.New("incorrect party")
	}

	ot.ferretCOT.RecvCot()

	return nil
}

func (ot *FerretOT) SendROT() error {
	ot.ferretCOT.SendRot()
	return nil
}

func (ot *FerretOT) RecvROT() error {
	ot.ferretCOT.RecvRot()
	return nil
}

func (ot *FerretOT) SenderGetBlockData(choice bool, index uint64) []byte {
	c := uint8(0)
	if choice {
		c = 1
	}
	return ot.ferretCOT.GetBlockData(c, index)
}

func (ot *FerretOT) ReceiverGetBlockData(index uint64) []byte {
	return ot.ferretCOT.GetBlockData(0, index)
}
