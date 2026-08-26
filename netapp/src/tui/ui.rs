use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Frame,
};

use super::app::AppState;

pub fn draw(frame: &mut Frame, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6),
            Constraint::Min(5),
            Constraint::Length(1),
        ])
        .split(frame.area());

    draw_iface_panel(frame, chunks[0], state);
    draw_proc_table(frame, chunks[1], state);
    draw_footer(frame, chunks[2]);
}

fn draw_iface_panel(frame: &mut Frame, area: Rect, state: &AppState) {
    let iface = &state.iface;
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Interface: {} (this NIC only) ", iface.name));

    let text = vec![
        Line::from(vec![
            Span::styled("RX  ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format!(
                "{:>10}/s   total {:>10}   {} pkts",
                human_bytes(iface.rx_rate),
                human_bytes(iface.rx_bytes as f64),
                iface.rx_packets
            )),
        ]),
        Line::from(vec![
            Span::styled("TX  ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format!(
                "{:>10}/s   total {:>10}   {} pkts",
                human_bytes(iface.tx_rate),
                human_bytes(iface.tx_bytes as f64),
                iface.tx_packets
            )),
        ]),
    ];

    frame.render_widget(Paragraph::new(text).block(block), area);
}

fn draw_proc_table(frame: &mut Frame, area: Rect, state: &AppState) {
    let header = Row::new(vec![
        Cell::from("PID"),
        Cell::from("PROCESS"),
        Cell::from("TCP TX/s"),
        Cell::from("TCP RX/s"),
        Cell::from("UDP TX/s"),
        Cell::from("UDP RX/s"),
    ])
    .style(Style::default().add_modifier(Modifier::BOLD));

    let rows = state.procs.iter().map(|p| {
        Row::new(vec![
            Cell::from(p.pid.to_string()),
            Cell::from(p.name.clone()),
            Cell::from(format!("{}/s", human_bytes(p.tcp_tx_rate))),
            Cell::from(format!("{}/s", human_bytes(p.tcp_rx_rate))),
            Cell::from(format!("{}/s", human_bytes(p.udp_tx_rate))),
            Cell::from(format!("{}/s", human_bytes(p.udp_rx_rate))),
        ])
    });

    let widths = [
        Constraint::Length(8),
        Constraint::Min(16),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Length(12),
    ];

    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(
                " Processes (system-wide, top {}) ",
                state.top_n
            )),
    );

    frame.render_widget(table, area);
}

fn draw_footer(frame: &mut Frame, area: Rect) {
    let text = Line::from(vec![Span::styled(
        "q/Ctrl-C quit -- process traffic is system-wide and not scoped to the interface above (sockets aren't tied to one NIC)",
        Style::default().fg(Color::DarkGray),
    )]);
    frame.render_widget(Paragraph::new(text), area);
}

fn human_bytes(v: f64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut val = v;
    let mut unit = 0;
    while val >= 1024.0 && unit < UNITS.len() - 1 {
        val /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{val:.0}{}", UNITS[unit])
    } else {
        format!("{val:.1}{}", UNITS[unit])
    }
}
