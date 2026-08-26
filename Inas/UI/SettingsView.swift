import SwiftUI
import UIKit

struct SettingsView: View {
    @Bindable var controller: ShareController
    @Environment(\.dismiss) private var dismiss

    private var sharing: Bool { controller.state.isSharing }

    var body: some View {
        NavigationStack {
            Form {
                Section {
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
                        .onChange(of: controller.credentials.password) { _, value in
                            if !value.isEmpty {
                                controller.credentials.usesCustomPassword = true
                            }
                            controller.persistCredentials()
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
                } header: {
                    Text("Sign-in")
                } footer: {
                    Text(sharing
                         ? "Stop sharing to change sign-in."
                         : "Leave the password empty to generate 8 letters and 4 numbers on Start.")
                }

                Section {
                    LabeledContent("Share") {
                        Text("inas")
                            .font(InasTheme.mono)
                            .foregroundStyle(.secondary)
                    }
                    LabeledContent("Protocol") {
                        Text("SMB 3")
                            .foregroundStyle(.secondary)
                    }
                    LabeledContent("Files") {
                        Text(filesHint)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.trailing)
                    }
                } header: {
                    Text("Share")
                } footer: {
                    Text("Other computers connect with the address shown after Start. Keep iNAS open while sharing.")
                }
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
        .presentationDetents([.medium, .large])
        .presentationDragIndicator(.visible)
    }

    private var filesHint: String {
        UIDevice.current.userInterfaceIdiom == .pad ? "On My iPad → iNAS" : "On My iPhone → iNAS"
    }

    private var autoPasswordBinding: Binding<Bool> {
        Binding(
            get: { !controller.credentials.usesCustomPassword },
            set: { auto in
                controller.credentials.usesCustomPassword = !auto
                if auto {
                    controller.credentials.password = ""
                }
                controller.persistCredentials()
            }
        )
    }
}
