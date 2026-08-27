// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import SwiftUI
import UIKit

struct ShareScreen: View {
    @Bindable var controller: ShareController
    @State private var showSettings = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                Spacer()
                StartStopButton(
                    state: controller.state,
                    action: controller.toggle
                )
                if case .failed(let message) = controller.state {
                    Text(message)
                        .font(.system(.subheadline, design: .rounded))
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 12)
                        .padding(.top, 20)
                }
                Spacer()
                if controller.state.isSharing {
                    sessionCard
                        .transition(.move(edge: .bottom).combined(with: .opacity))
                        .padding(.bottom, 24)
                }
                Text("v\(appVersion)")
                    .font(.system(.caption, design: .rounded).weight(.semibold))
                    .foregroundStyle(.tertiary)
                    .accessibilityLabel("Version \(appVersion)")
            }
            .padding(.horizontal, 24)
            .frame(maxWidth: 560)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(background.ignoresSafeArea())
            .navigationTitle("iNAS")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        showSettings = true
                    } label: {
                        Image(systemName: "gearshape")
                            .font(.body.weight(.semibold))
                    }
                    .accessibilityLabel("Settings")
                }
            }
            .sheet(isPresented: $showSettings) {
                SettingsView(controller: controller)
            }
            .animation(.easeInOut(duration: 0.28), value: controller.state.isSharing)
        }
    }

    private var appVersion: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.0.1"
    }

    private var sessionCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            sessionRow(label: "Mac", value: controller.connectionURL, copy: controller.connectionURL)
            if let windows = controller.endpoint?.windowsHint {
                sessionRow(label: "Windows", value: windows, copy: windows)
            }
            if let name = controller.endpoint?.windowsNameHint {
                sessionRow(label: "Windows name", value: name, copy: name)
            }
            sessionRow(label: "User", value: controller.credentials.username, copy: controller.credentials.username)
            sessionRow(label: "Password", value: controller.credentials.password, copy: controller.credentials.password)
        }
        .padding(18)
        .background(cardBackground)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Share credentials")
    }

    private func sessionRow(label: String, value: String, copy: String, secret: Bool = false) -> some View {
        Button {
            UIPasteboard.general.string = copy
        } label: {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(label)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    Text(secret ? "••••••••" : value)
                        .font(InasTheme.mono)
                        .foregroundStyle(.primary)
                        .textSelection(.enabled)
                }
                Spacer(minLength: 12)
                Image(systemName: "doc.on.doc")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .buttonStyle(.plain)
        .accessibilityLabel(label)
        .accessibilityValue(secret ? "Hidden" : value)
        .accessibilityHint("Copies \(label.lowercased())")
    }

    private var cardBackground: some View {
        RoundedRectangle(cornerRadius: 20, style: .continuous)
            .fill(InasTheme.cardFill)
            .overlay(
                RoundedRectangle(cornerRadius: 20, style: .continuous)
                    .strokeBorder(InasTheme.cardStroke)
            )
    }

    private var background: some View {
        LinearGradient(
            colors: [
                Color(uiColor: .systemBackground),
                Color(uiColor: .secondarySystemBackground)
            ],
            startPoint: .top,
            endPoint: .bottom
        )
    }
}

#Preview {
    ShareScreen(controller: ShareController())
}
