import SwiftUI

/// The Tessera mark: four colored tiles, matching the app icon.
struct MosaicLogo: View {
    var size: CGFloat = 72

    var body: some View {
        let gap = size * 0.06
        let tile = (size - gap) / 2
        VStack(spacing: gap) {
            HStack(spacing: gap) { square(0, tile); square(1, tile) }
            HStack(spacing: gap) { square(2, tile); square(3, tile) }
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }

    private func square(_ index: Int, _ side: CGFloat) -> some View {
        RoundedRectangle(cornerRadius: side * 0.22, style: .continuous)
            .fill(Theme.tileColors[index])
            .frame(width: side, height: side)
    }
}
