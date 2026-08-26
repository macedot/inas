// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import SwiftUI

struct StartStopButton: View {
    let state: ShareController.State
    let action: () -> Void

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var pulse = false

    private var isConnecting: Bool {
        state == .starting || state == .stopping
    }

    private var isLive: Bool {
        state.isSharing || state == .stopping
    }

    private var title: String {
        switch state {
        case .stopped, .failed: "Start"
        case .starting: "Connecting"
        case .sharing: "Stop"
        case .stopping: "Stopping"
        }
    }

    var body: some View {
        Button(action: action) {
            ZStack {
                Circle()
                    .fill(isLive ? InasTheme.sharing : InasTheme.stopped)
                    .shadow(
                        color: (isLive ? InasTheme.sharing : .clear).opacity(0.45),
                        radius: pulse && isLive && !isConnecting && !reduceMotion ? 28 : 12
                    )

                Circle()
                    .strokeBorder(.white.opacity(0.22), lineWidth: 2)

                if isConnecting {
                    TimelineView(.animation(minimumInterval: 1.0 / 30.0, paused: reduceMotion)) { timeline in
                        let turns = timeline.date.timeIntervalSinceReferenceDate / 0.85
                        let angle = reduceMotion ? 0.0 : (turns.truncatingRemainder(dividingBy: 1) * 360)
                        Circle()
                            .trim(from: 0.08, to: 0.42)
                            .stroke(
                                .white,
                                style: StrokeStyle(lineWidth: 5, lineCap: .round)
                            )
                            .padding(7)
                            .rotationEffect(.degrees(angle))
                            .accessibilityHidden(true)
                    }
                }

                VStack(spacing: 6) {
                    if !isConnecting {
                        Image(systemName: isLive ? "stop.fill" : "play.fill")
                            .font(.system(size: 34, weight: .semibold))
                            .offset(x: isLive ? 0 : 3)
                    }
                    Text(title)
                        .font(.system(.title2, design: .rounded).weight(.bold))
                        .contentTransition(.opacity)
                }
                .foregroundStyle(.white)
            }
            .frame(width: 168, height: 168)
        }
        .buttonStyle(.plain)
        .accessibilityLabel(title)
        .accessibilityValue(accessibilityValue)
        .accessibilityAddTraits(.startsMediaSession)
        .onChange(of: isConnecting) { _, connecting in
            if connecting {
                pulse = false
            } else {
                updatePulse(isLive)
            }
        }
        .onChange(of: isLive) { _, live in
            updatePulse(live)
        }
        .onAppear {
            updatePulse(isLive)
        }
    }

    private var accessibilityValue: String {
        switch state {
        case .stopped, .failed: "Sharing is off"
        case .starting: "Connecting"
        case .sharing: "Sharing is on"
        case .stopping: "Stopping"
        }
    }

    private func updatePulse(_ live: Bool) {
        if reduceMotion || !live || isConnecting {
            pulse = false
            return
        }
        withAnimation(.easeInOut(duration: 1.6).repeatForever(autoreverses: true)) {
            pulse = true
        }
    }
}
