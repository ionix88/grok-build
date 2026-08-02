# frozen_string_literal: true

# Homebrew formula skeleton for the public Orca CLI.
# Bottle URLs and SHA-256 digests are filled at release promotion (Task 55+).
class Orca < Formula
  desc "Orca terminal AI coding host"
  homepage "https://github.com/example/orca"
  version "0.0.0-dev"
  license "Apache-2.0"

  # url "https://example.invalid/orca/#{version}/orca-darwin-aarch64.tar.gz"
  # sha256 "REPLACE_AT_RELEASE"

  def install
    bin.install "orca"
  end

  test do
    assert_match "orca", shell_output("#{bin}/orca --version")
  end
end
