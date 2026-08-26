import SwiftUI

struct StartStopButton: View {
    let state: ShareController.State
    let action: () -> Void

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var spinAngle: Double = 0
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
                    Circle()
                        .trim(from: 0.08, to: 0.42)
                        .stroke(
                            .white,
                            style: StrokeStyle(lineWidth: 5, lineCap: .round)
                        )
                        .padding(7)
                        .rotationEffect(.degrees(spinAngle))
                        .accessibilityHidden(true)
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
            updateSpin(connecting)
        }
        .onChange(of: isLive) { _, live in
            updatePulse(live)
        }
        .onAppear {
            updateSpin(isConnecting)
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

    private func updateSpin(_ connecting: Bool) {
        if reduceMotion || !connecting {
            withAnimation(.easeOut(duration: 0.2)) {
                spinAngle = 0
            }
            return
        }
        spinAngle = 0
        withAnimation(.linear(duration: 0.85).repeatForever(autoreverses: false)) {
            spinAngle = 360
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
