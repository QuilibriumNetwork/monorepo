//
// Copyright (c) 2020-2023 Markku Rossi
//
// All rights reserved.
//

package circuit

import (
	"fmt"
	"os"
	"time"

	"github.com/markkurossi/tabulate"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/p2p"
)

// Timing records timing samples and renders a profiling report.
type Timing struct {
	Start   time.Time
	Samples []*Sample
}

// NewTiming creates a new Timing instance.
func NewTiming() *Timing {
	return &Timing{
		Start: time.Now(),
	}
}

// Sample adds a timing sample with label and data columns.
func (t *Timing) Sample(label string, cols []string) *Sample {
	start := t.Start
	if len(t.Samples) > 0 {
		start = t.Samples[len(t.Samples)-1].End
	}
	sample := &Sample{
		Label: label,
		Start: start,
		End:   time.Now(),
		Cols:  cols,
	}
	t.Samples = append(t.Samples, sample)
	return sample
}

// Print prints profiling report to standard output.
func (t *Timing) Print(stats p2p.IOStats) {
	if len(t.Samples) == 0 {
		return
	}

	sent := stats.Sent.Load()
	received := stats.Recvd.Load()
	flushed := stats.Flushed.Load()

	tab := tabulate.New(tabulate.UnicodeLight)
	tab.Header("Op").SetAlign(tabulate.ML)
	tab.Header("Time").SetAlign(tabulate.MR)
	tab.Header("%").SetAlign(tabulate.MR)
	tab.Header("Xfer").SetAlign(tabulate.MR)

	total := t.Samples[len(t.Samples)-1].End.Sub(t.Start)
	for _, sample := range t.Samples {
		row := tab.Row()
		row.Column(sample.Label)

		duration := sample.End.Sub(sample.Start)
		row.Column(fmt.Sprintf("%s", duration.String()))
		row.Column(fmt.Sprintf("%.2f%%",
			float64(duration)/float64(total)*100))

		for _, col := range sample.Cols {
			row.Column(col)
		}

		for idx, sub := range sample.Samples {
			row := tab.Row()

			var prefix string
			if idx+1 >= len(sample.Samples) {
				prefix = "\u2570\u2574"
			} else {
				prefix = "\u251C\u2574"
			}

			row.Column(prefix + sub.Label).SetFormat(tabulate.FmtItalic)

			var d time.Duration
			if sub.Abs > 0 {
				d = sub.Abs
			} else {
				d = sub.End.Sub(sub.Start)
			}
			row.Column(d.String()).SetFormat(tabulate.FmtItalic)

			row.Column(
				fmt.Sprintf("%.2f%%", float64(d)/float64(duration)*100)).
				SetFormat(tabulate.FmtItalic)
		}
	}
	row := tab.Row()
	row.Column("Total").SetFormat(tabulate.FmtBold)
	row.Column(t.Samples[len(t.Samples)-1].End.Sub(t.Start).String()).
		SetFormat(tabulate.FmtBold)
	row.Column("").SetFormat(tabulate.FmtBold)
	row.Column(FileSize(sent + received).String()).SetFormat(tabulate.FmtBold)

	row = tab.Row()
	row.Column("\u251C\u2574Sent").SetFormat(tabulate.FmtItalic)
	row.Column("")
	row.Column(
		fmt.Sprintf("%.2f%%", float64(sent)/float64(sent+received)*100)).
		SetFormat(tabulate.FmtItalic)
	row.Column(FileSize(sent).String()).SetFormat(tabulate.FmtItalic)

	row = tab.Row()
	row.Column("\u251C\u2574Rcvd").SetFormat(tabulate.FmtItalic)
	row.Column("")
	row.Column(
		fmt.Sprintf("%.2f%%", float64(received)/float64(sent+received)*100)).
		SetFormat(tabulate.FmtItalic)
	row.Column(FileSize(received).String()).SetFormat(tabulate.FmtItalic)

	row = tab.Row()
	row.Column("\u2570\u2574Flcd").SetFormat(tabulate.FmtItalic)
	row.Column("")
	row.Column("")
	row.Column(fmt.Sprintf("%v", flushed)).SetFormat(tabulate.FmtItalic)

	tab.Print(os.Stdout)
}

// Sample contains information about one timing sample.
type Sample struct {
	Label   string
	Start   time.Time
	End     time.Time
	Abs     time.Duration
	Cols    []string
	Samples []*Sample
}

// SubSample adds a sub-sample for a timing sample.
func (s *Sample) SubSample(label string, end time.Time) {
	start := s.Start
	if len(s.Samples) > 0 {
		start = s.Samples[len(s.Samples)-1].End
	}
	s.Samples = append(s.Samples, &Sample{
		Label: label,
		Start: start,
		End:   end,
	})
}

// AbsSubSample adds an absolute sub-sample for a timing sample.
func (s *Sample) AbsSubSample(label string, duration time.Duration) {
	s.Samples = append(s.Samples, &Sample{
		Label: label,
		Abs:   duration,
	})
}
