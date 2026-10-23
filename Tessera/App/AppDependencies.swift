import Foundation
import TesseraCore

/// Composition root: builds the services once and shares them with `AppState`.
final class AppDependencies {
    let store: SecureAssetStore
    let repository: LibraryRepository
    let certificates: CertificateManager
    let validation: ValidationService
    let importService: IPAImportService
    let coordinator: SigningCoordinator
    let export: ExportService
    let distribution: DistributionService
    let installation: InstallationService
    let downloads: DownloadService

    init(
        store: SecureAssetStore,
        repository: LibraryRepository,
        certificates: CertificateManager,
        validation: ValidationService,
        importService: IPAImportService,
        coordinator: SigningCoordinator,
        export: ExportService,
        distribution: DistributionService,
        installation: InstallationService,
        downloads: DownloadService
    ) {
        self.store = store
        self.repository = repository
        self.certificates = certificates
        self.validation = validation
        self.importService = importService
        self.coordinator = coordinator
        self.export = export
        self.distribution = distribution
        self.installation = installation
        self.downloads = downloads
    }

    static func make() throws -> AppDependencies {
        let store = try SecureAssetStore()
        // Anything left in the temporary workspace is from an interrupted run.
        store.cleanTemporaryFiles()

        let repository = LibraryRepository(directory: store.root)
        let certificates = CertificateManager()
        let validation = ValidationService()
        let metadata = MetadataService(store: store)
        let importService = IPAImportService(
            store: store, metadataService: metadata, validation: validation, repository: repository
        )
        // The signing engine stays "unavailable" until a real implementation has been verified on-device.
        let coordinator = SigningCoordinator(
            engine: UnavailableSigningEngine(),
            validation: validation,
            certificates: certificates,
            store: store,
            repository: repository
        )
        return AppDependencies(
            store: store,
            repository: repository,
            certificates: certificates,
            validation: validation,
            importService: importService,
            coordinator: coordinator,
            export: ExportService(store: store),
            distribution: DistributionService(),
            installation: InstallationService(),
            downloads: DownloadService()
        )
    }
}
