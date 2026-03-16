package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var helpStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#626262")).Render

const (
	headerHeight = 12
	footerHeight = 1
)

type ScannerMsg struct {
	Result         *ScanResult
	Scanned        int
	Total          int
	Working        int
	ExpansionQueue int
	ProxyDetected  bool
	ProxyChecked   bool
	Done           bool
}

type model struct {
	progress      progress.Model
	viewport      viewport.Model
	results       []string
	scanned       int
	total         int
	working       int
	queue         int
	proxyDetected bool
	proxyChecked  bool
	done          bool
	width         int
	height        int
	domain        string
}

func newModel(domain string) model {
	return model{
		progress: progress.New(progress.WithDefaultGradient()),
		viewport: viewport.New(0, 0),
		results:  []string{},
		domain:   domain,
	}
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.progress.Width = msg.Width - 10
		m.viewport.Width = msg.Width - 4
		m.viewport.Height = msg.Height - headerHeight - footerHeight
		return m, nil

	case ScannerMsg:
		if msg.ProxyChecked {
			m.proxyChecked = true
			m.proxyDetected = msg.ProxyDetected
		}
		if msg.Result != nil {
			r := msg.Result
			m.scanned = msg.Scanned
			m.total = msg.Total
			m.working = msg.Working
			m.queue = msg.ExpansionQueue

			if r.Status == statusWorking && r.Tunnel != nil && r.Tunnel.Score() > 0 {
				line := fmt.Sprintf("%-18s %d/6 %4dms %s", r.Host, r.Tunnel.Score(), r.LatencyMs, r.Tunnel.Details())
				if r.Tunnel.Score() == 6 {
					line = lipgloss.NewStyle().Foreground(lipgloss.Color("#4CAF50")).Render("* " + line)
				} else {
					line = "  " + line
				}
				m.results = append(m.results, line)
				m.viewport.SetContent(strings.Join(m.results, "\n"))
				m.viewport.GotoBottom()
			}
		}
		if msg.Done {
			m.done = true
			return m, tea.Quit
		}
		return m, nil
	}
	return m, nil
}

func (m model) View() string {
	if m.width == 0 {
		return "Initializing..."
	}

	proxyInfo := ""
	if m.proxyChecked {
		if m.proxyDetected {
			proxyInfo = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5555")).Render("  ⚠ Transparent Proxy: DETECTED")
		} else {
			proxyInfo = lipgloss.NewStyle().Foreground(lipgloss.Color("#55FF55")).Render("  ✔ Transparent Proxy: None")
		}
	}

	header := lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("62")).
		Padding(0, 1).
		Render(
			fmt.Sprintf("SlipNet DNS Scanner - Domain: %s\n", m.domain) +
				proxyInfo + "\n\n" +
				fmt.Sprintf("Scanned: %d / %d  |  Working: %d  |  Queue: %d\n\n", m.scanned, m.total, m.working, m.queue) +
				m.progress.ViewAs(float64(m.scanned)/float64(m.total)),
		)

	content := lipgloss.NewStyle().
		Padding(0, 1).
		Render(m.viewport.View())

	footer := helpStyle("  Press 'q' to stop scan")

	return header + "\n" + content + "\n" + footer
}

// RunTUI starts the Bubble Tea program.
func RunTUI(domain string, updateCh chan ScannerMsg) {
	p := tea.NewProgram(newModel(domain))

	go func() {
		for msg := range updateCh {
			p.Send(msg)
		}
	}()

	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running TUI: %v\n", err)
	}
}
