// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import SwiftUI
import UIKit
import UniformTypeIdentifiers

struct SettingsView: View {
    @Bindable var controller: ShareController
    @Environment(\.dismiss) private var dismiss
    @State private var pickingShareID: UUID?
    @State private var signInExpanded = false
    @State private var sharesExpanded = false

    private var sharing: Bool { controller.state.isSharing }

    private var signInSummary: String {
        let user = controller.credentials.username.trimmingCharacters(in: .whitespacesAndNewlines)
        let password = controller.credentials.usesCustomPassword ? "custom password" : "auto password"
        return "\(user.isEmpty ? "—" : user) · \(password)"
    }

    private var sharesSummary: String {
        let count = 1 + controller.extras.count
        return "\(count) share\(count == 1 ? "" : "s")"
    }

    var body: some View {
        NavigationStack {
            Form {
                signInSection
                shareSection
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .fileImporter(
                isPresented: Binding(
                    get: { pickingShareID != nil },
                    set: { if !$0 { pickingShareID = nil } }
                ),
                allowedContentTypes: [.folder],
                allowsMultipleSelection: false
            ) { result in
                guard let id = pickingShareID else { return }
                pickingShareID = nil
                if case .success(let urls) = result, let url = urls.first {
                    controller.setShareFolder(url, id: id)
                }
            }
        }
        .presentationDetents([.medium, .large])
        .presentationDragIndicator(.visible)
    }

    private var signInSection: some View {
        Section {
            DisclosureGroup(isExpanded: $signInExpanded) {
                TextField("User", text: $controller.credentials.username)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .textContentType(.username)
                    .font(InasTheme.mono)
                    .disabled(sharing)
                    .onChange(of: controller.credentials.username) { _, _ in
                        controller.persistCredentials()
                    }
                    .accessibilityLabel("Username")

                HStack {
                    Group {
                        if controller.showPassword {
                            TextField("Password", text: $controller.credentials.password)
                        } else {
                            SecureField("Leave empty to generate", text: $controller.credentials.password)
                        }
                    }
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .textContentType(.password)
                    .font(InasTheme.mono)
                    .disabled(sharing)
                    .onChange(of: controller.credentials.password) { _, _ in
                        controller.passwordDidChange()
                    }

                    Button {
                        controller.showPassword.toggle()
                    } label: {
                        Image(systemName: controller.showPassword ? "eye.slash" : "eye")
                    }
                    .accessibilityLabel(controller.showPassword ? "Hide password" : "Show password")
                }

                Toggle("New password each Start", isOn: autoPasswordBinding)
                    .disabled(sharing)
                    .accessibilityHint("When on, iNAS creates a fresh password every time you start sharing.")
            } label: {
                CardHeader(icon: "person.crop.circle", title: "Sign-in", summary: signInSummary)
            }
            .animation(.easeInOut(duration: 0.2), value: signInExpanded)
            .accessibilityElement(children: .contain)
        } header: {
            Text("Account")
        } footer: {
            Text(sharing
                 ? "Stop sharing to change sign-in."
                 : "Leave the password empty to generate 8 letters and 4 numbers on Start.")
        }
    }

    private var shareSection: some View {
        Section {
            DisclosureGroup(isExpanded: $sharesExpanded) {
                LabeledContent("inas") {
                    Text("iNAS folder")
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.trailing)
                }
                ForEach(controller.extras) { extra in
                    extraRow(extra)
                }
                if controller.canAddShare {
                    Button {
                        controller.addShare()
                    } label: {
                        Label("Add share", systemImage: "plus")
                    }
                    .disabled(sharing)
                }
                LabeledContent("Protocol") {
                    Text("SMB 3")
                        .foregroundStyle(.secondary)
                }
            } label: {
                CardHeader(icon: "folder", title: "Shares", summary: sharesSummary)
            }
            .animation(.easeInOut(duration: 0.2), value: sharesExpanded)
            .accessibilityElement(children: .contain)
        } header: {
            Text("Folders")
        } footer: {
            Text(sharing
                 ? "Stop sharing to change folders and names."
                 : "Each extra share needs a name (letters, numbers, _ or -) and a folder. Connect with smb://host/name.")
        }
    }

    private func extraRow(_ extra: ExtraShare) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                TextField("Share name", text: nameBinding(extra.id))
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .font(InasTheme.mono)
                    .disabled(sharing)
                    .onChange(of: extra.name) { _, _ in
                        controller.persistShares()
                    }
                Button(role: .destructive) {
                    controller.removeShare(id: extra.id)
                } label: {
                    Image(systemName: "minus.circle.fill")
                }
                .disabled(sharing)
                .accessibilityLabel("Remove share")
            }
            Button {
                pickingShareID = extra.id
            } label: {
                HStack {
                    Text(extra.folderTitle.isEmpty ? "Choose folder" : extra.folderTitle)
                        .foregroundStyle(extra.folderTitle.isEmpty ? .secondary : .primary)
                    Spacer()
                    Image(systemName: "folder")
                        .foregroundStyle(.secondary)
                }
            }
            .disabled(sharing)
            .accessibilityLabel("Share folder")
        }
    }

    private func nameBinding(_ id: UUID) -> Binding<String> {
        Binding(
            get: { controller.extras.first(where: { $0.id == id })?.name ?? "" },
            set: { controller.setShareName($0, id: id) }
        )
    }

    private var autoPasswordBinding: Binding<Bool> {
        Binding(
            get: { !controller.credentials.usesCustomPassword },
            set: { controller.setGeneratesPasswordEachStart($0) }
        )
    }
}
