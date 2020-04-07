//
//  CertificatePinningManager.m
//  CertificatePinning
//
//  Created by Mirza Zuhaib Beg on 03/04/20.
//  Copyright © Mirza Zuhaib Beg. All rights reserved.
//

#import "CertificatePinningManager.h"
#import <CommonCrypto/CommonDigest.h>

// List of available trusted root certificates in iOS 13, iPadOS 13, macOS 10.15, watchOS 6, and tvOS 13
// https://support.apple.com/en-in/HT210770

static NSString *kRootCA1                 = @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

static NSString *kRootCA2                 = @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

static NSString *kRootCA3                 = @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

static NSString *kRootCA4                 = @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

static NSString *kRootCA5 = @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

@interface CertificatePinningManager()

@property (nonatomic, strong) NSMutableArray *arrayCertificatePinned;

@end

@implementation CertificatePinningManager

#pragma mark - NSURLSessionDelegate Methods

- (void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential * _Nullable credential))completionHandler {
    
    SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
    NSInteger count = (NSInteger)SecTrustGetCertificateCount(serverTrust);
    
    BOOL certificatePinned = NO;
    
    for (int index = 0; index < count; index++) {
        SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, index);
        NSData *remoteCertificateData = CFBridgingRelease(SecCertificateCopyData(certificate));
        NSData *sha256 = [self getSHA256:remoteCertificateData];
        NSString *hexString = [self getHexString:sha256];
        if ([self isCertificatePinnned:hexString]) {
            certificatePinned = YES;
            break;
        }
    }
    
    if (certificatePinned) {
       NSURLCredential *credential = [NSURLCredential credentialForTrust:serverTrust];
        [[challenge sender] useCredential:credential forAuthenticationChallenge:challenge];
        completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
    } else {
        [[challenge sender] cancelAuthenticationChallenge:challenge];
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
    }
}

#pragma mark - Private Methods

/// Method to return is Certificate Pinnned
/// @param fingerprint fingerprint
-(BOOL)isCertificatePinnned:(NSString*)fingerprint {
    
    if (self.arrayCertificatePinned == nil) {
        self.arrayCertificatePinned = [[NSMutableArray alloc] init];
        [self.arrayCertificatePinned addObject:kRootCA1];
        [self.arrayCertificatePinned addObject:kRootCA2];
        [self.arrayCertificatePinned addObject:kRootCA3];
        [self.arrayCertificatePinned addObject:kRootCA4];
        [self.arrayCertificatePinned addObject:kRootCA5];
    }
    
    for (NSString *certificateFingerPrint in self.arrayCertificatePinned) {
        if ([certificateFingerPrint isEqualIgnoreCaseToString:fingerprint]) {
            return YES;
        }
    }
    
    return NO;
}

/// Method to getSHA 256
/// @param data data
-(NSData *)getSHA256:(NSData*)data {
    NSMutableData *macOut = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, data.length, macOut.mutableBytes);
    return macOut;
}

/// Method to get Hex String
/// @param data data
- (NSString *)getHexString:(NSData*)data {
    const unsigned char *bytes = (const unsigned char *)data.bytes;
    NSMutableString *hex = [NSMutableString new];
    for (NSInteger i = 0; i < data.length; i++) {
        [hex appendFormat:@"%02x", bytes[i]];
    }
    return [hex copy];
}

@end

