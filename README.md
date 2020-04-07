# CertificatePinning

Create instance of TRCertificatePinningManager class and set it as delegate to NSURLSession.

TRCertificatePinningManager *certificatePinningManager = [[TRCertificatePinningManager alloc] init];
NSURLSession *session = [NSURLSession sessionWithConfiguration:configuration delegate:certificatePinningManager delegateQueue:nil];
