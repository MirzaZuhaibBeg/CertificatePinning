# CertificatePinning

Create instance of CertificatePinningManager class and set it as delegate to NSURLSession.

CertificatePinningManager *certificatePinningManager = [[CertificatePinningManager alloc] init];

NSURLSession *session = [NSURLSession sessionWithConfiguration:configuration delegate:certificatePinningManager delegateQueue:nil];
