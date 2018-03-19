//
//  JWTCryptoKey.m
//  JWT
//
//  Created by Lobanov Dmitry on 04.02.17.
//  Copyright © 2017 JWTIO. All rights reserved.
//

#import "JWTCryptoKey.h"
#import "JWTCryptoSecurity.h"
#import "JWTBase64Coder.h"
#import "JWT_ASN1_Coding.h"
@interface JWTCryptoKeyBuilder()
+ (NSString *)keyTypeRSA;
+ (NSString *)keyTypeEC;
@property (assign, nonatomic, readwrite) BOOL public;
@property (assign, nonatomic, readwrite) NSString *keyType;
@property (nonatomic, readonly) BOOL withKeyTypeRSA;
@property (nonatomic, readonly) BOOL withKeyTypeEC;
@end
@implementation JWTCryptoKeyBuilder
+ (NSString *)keyTypeRSA {
    return @"RSA";
}
+ (NSString *)keyTypeEC {
    return @"EC";
}
- (instancetype)keyTypeRSA {
    self.keyType = [self.class keyTypeRSA];
    return self;
}
- (instancetype)keyTypeEC {
    self.keyType = [self.class keyTypeEC];
    return self;
}
- (BOOL)withKeyTypeRSA {
    return [self.keyType isEqualToString:self.class.keyTypeRSA];
}
- (BOOL)withKeyTypeEC {
    return [self.keyType isEqualToString:self.class.keyTypeEC];
}
@end
@interface JWTCryptoKey ()
@property (copy, nonatomic, readwrite) NSString *tag;
@property (assign, nonatomic, readwrite) SecKeyRef key;
@property (copy, nonatomic, readwrite) NSData *rawKey;
@end
@interface JWTCryptoKey (Class)
+ (NSString *)uniqueTag;
@end
@implementation JWTCryptoKey (Class)
+ (NSString *)uniqueTag {
    return [[NSUUID UUID].UUIDString stringByReplacingOccurrencesOfString:@"-" withString:@""].lowercaseString;
}
@end
@implementation JWTCryptoKey (Parameters)
+ (NSString *)parametersKeyBuilder {
    return NSStringFromSelector(_cmd);
}
@end
@interface JWTCryptoKey (ParametersExtraction)
- (NSString *)extractedSecKeyTypeWithParameters:(NSDictionary *)parameters;
- (JWTCryptoKeyBuilder *)extractedBuilderWithParameters:(NSDictionary *)parameters;
@end
// Consider that both methods in this category should return non-nullable values
@implementation JWTCryptoKey (ParametersExtraction)
// Parameters are nil at that moment, could be used later for some purposes
- (JWTCryptoKeyBuilder *)extractedBuilderWithParameters:(NSDictionary *)parameters {
    return (JWTCryptoKeyBuilder *)parameters[[self.class parametersKeyBuilder]] ?: [JWTCryptoKeyBuilder new].keyTypeRSA;
}
// Parameters are nil at that moment, could be used later for some purposes
- (NSString *)extractedSecKeyTypeWithParameters:(NSDictionary *)parameters {
    JWTCryptoKeyBuilder *builder = [self extractedBuilderWithParameters:parameters];
    NSString *result = nil;
    if (builder.withKeyTypeEC) {
        result = [JWTCryptoSecurity keyTypeEC];
    }
    return result ?: [JWTCryptoSecurity keyTypeRSA];
}
@end
@interface JWTCryptoKey (Generator) <JWTCryptoKey__Generator__Protocol, JWTCryptoKey__Raw__Generator__Protocol>
@end

@implementation JWTCryptoKey (Generator)
- (instancetype)initWithSecKeyRef:(SecKeyRef)key {
    self = [super init];
    if (key != NULL) {
        self.key = key;
    }
    else {
        return nil;
    }
    return self;
}
- (instancetype)initWithData:(NSData *)data parameters:(NSDictionary *)parameters error:(NSError *__autoreleasing*)error {
    // add check that everything is fine.
    return [super init];
}
- (instancetype)initWithBase64String:(NSString *)base64String parameters:(NSDictionary *)parameters error:(NSError *__autoreleasing*)error {
    return [self initWithData:[JWTBase64Coder dataWithBase64UrlEncodedString:base64String] parameters:parameters error:error];
}
- (instancetype)initWithPemEncoded:(NSString *)encoded parameters:(NSDictionary *)parameters error:(NSError *__autoreleasing*)error {
    //TODO: check correctness.
    //maybe use clean initWithBase64String and remove ?: encoded tail.
    NSString *clean = [JWTCryptoSecurity keyFromPemFileContent:encoded] ?: encoded;//[JWTCryptoSecurity stringByRemovingPemHeadersFromString:encoded];
    return [self initWithBase64String:clean parameters:parameters error:error];
}
- (instancetype)initWithPemAtURL:(NSURL *)url parameters:(NSDictionary *)parameters error:(NSError *__autoreleasing*)error {
    // contents of url
    NSError *contentsExtractingError = nil;
    NSString *pemEncoded = [NSString stringWithContentsOfURL:url encoding:NSUTF8StringEncoding error:&contentsExtractingError];
    if (error && contentsExtractingError) {
        *error = contentsExtractingError;
        return nil;
    }
    return [self initWithPemEncoded:pemEncoded parameters:parameters error:error];
}
@end

@implementation JWTCryptoKey (Check)
- (void)cleanup {
    if (self.key != NULL) {
        CFRelease(self.key);
    }
}

- (instancetype)checkedWithError:(NSError *__autoreleasing*)error {
    BOOL checked = self.key != NULL;
    if (error && !checked) {
        *error = [NSError errorWithDomain:@"org.opensource.jwt.security.key" code:-200 userInfo:@{NSLocalizedDescriptionKey : @"Security key not retrieved! something went wrong!"}];
    }
    return self;
}
@end

@implementation JWTCryptoKey
- (void)dealloc {
    [self cleanup];
}
@end

@implementation JWTCryptoKeyPublic
- (instancetype)initWithData:(NSData *)data parameters:(NSDictionary *)parameters error:(NSError *__autoreleasing*)error {
    self = [super initWithData:data parameters:parameters error:error];
    if (self) {
        self.tag = [self.class uniqueTag];

        if (!data) {
            return nil;
        }

        NSError *removingHeaderError = nil;
        // asks builder
        
        JWTCryptoKeyBuilder *builder = [self extractedBuilderWithParameters:parameters];
        NSData *keyData = data;
        if (builder.withKeyTypeRSA) {
            keyData = [JWTCryptoSecurity dataByRemovingPublicKeyHeader:data error:&removingHeaderError];
            if (!keyData || removingHeaderError) {
                if (error && removingHeaderError != nil) {
                    *error = removingHeaderError;
                }
                return nil;
            }
        }
        
        if (builder.withKeyTypeEC) {
            NSData *theData = [data copy];
            SecKeyRef privateKeyRef = NULL;
            JWT__ASN1__Coder *coder = [JWT__ASN1__Coder new];
            {
                // try decode by asn1 coder.
                NSError *theError = nil;
                NSArray *items = [[coder parsedData:theData error:&theError] items];
                NSLog(@"items: %@", [items valueForKey:@"debugInformation"]);
            }
//            {
//                // try decode.
//                NSData *privateKeyData = [JWTCryptoSecurity__ASN1__Coder decodedItemsFromData:data isPublic:YES error:nil][[JWTCryptoSecurity__ASN1__Coder parametersKeyPublicKeyData]];
//                NSError *thisError = nil;
//                SecKeyRef ref;
//                if (privateKeyData) {
//                    ref = [JWTCryptoSecurity addKeyWithData:privateKeyData asPublic:YES tag:self.tag type:[self extractedSecKeyTypeWithParameters:parameters] error:&thisError];
//                }
//                if (!thisError && ref) {
//                    // ok!
//                }
//                NSLog(@"thisError: %@ SecKeyRef: %@", thisError, ref);
//            }
            
            NSError *theError = nil;
            keyData = [JWTCryptoSecurity dataByExtractingPublicKeyFromANS1:data error:&theError];
            if (!keyData || theError) {
                if (error && theError != nil) {
                    *error = theError;
                }
                return nil;
            }
            // unknown here.
            // process keyData before passing it to JWTCryptoSecurity+addKey... method.
//            keyData = [JWTCryptoSecurity dataByRemovingPublicKeyHeader:data error:&removingHeaderError];
//            if (!keyData || removingHeaderError) {
//                if (error && removingHeaderError != nil) {
//                    *error = removingHeaderError;
//                }
//                return nil;
//            }
//            NSData *theData = [data copy];
//            while (theData != nil && theData.length > 0) {
//                NSError *theError = nil;
//                self.key = [JWTCryptoSecurity addKeyWithData:theData asPublic:YES tag:self.tag type:[self extractedSecKeyTypeWithParameters:parameters] error:&theError];
//                NSLog(@"theData: %@", theData);
//                NSLog(@"theError: %@", theError);
//                if (!theError && self.key) {
//                    NSLog(@"Found!");
//                    NSLog(@"theData: %@", theData);
//                    NSLog(@"theKey: %@", self.key);
//                    break;
//                }
//                NSUInteger length = theData.length - 1;
//                NSRange range = NSMakeRange(1, length);
//                theData = [NSData dataWithBytes:((char *)theData.bytes) + range.location length:range.length];
//            }
        }

        NSError *addKeyError = nil;
        
        self.key = [JWTCryptoSecurity addKeyWithData:keyData asPublic:YES tag:self.tag type:[self extractedSecKeyTypeWithParameters:parameters] error:&addKeyError];
        if (!self.key || addKeyError) {
            if (error && addKeyError != nil) {
                *error = addKeyError;
            }
            [self cleanup];
            return nil;
        }
    }
    return self;
}
- (instancetype)initWithCertificateData:(NSData *)certificateData parameters:(NSDictionary *)parameters error:(NSError *__autoreleasing*)error {
    SecKeyRef key = [JWTCryptoSecurity publicKeyFromCertificate:certificateData];
    if (!key) {
        // error: Public certificate incorrect.
        return nil;
    }

    if (self = [super init]) {
        self.key = key;
    }

    return self;
}
- (instancetype)initWithCertificateBase64String:(NSString *)certificate parameters:(NSDictionary *)parameters error:(NSError *__autoreleasing*)error {
    // cleanup certificate if needed.
    // call initWithCertificateData:(NSData *)certificateData
    NSData *certificateData = nil;
    return [self initWithCertificateData:certificateData parameters:parameters error:error];
}
@end

@implementation JWTCryptoKeyPrivate
- (instancetype)initWithData:(NSData *)data parameters:(NSDictionary *)parameters error:(NSError *__autoreleasing*)error {
    self = [super initWithData:data parameters:parameters error:error];
    if (self) {
        self.tag = [self.class uniqueTag];
        NSError *addKeyError = nil;
        if (!data) {
            // error: no data?
            // or put it in superclass?
            return nil;
        }
        
        NSData *theData = [data copy];
        JWTCryptoKeyBuilder *builder = [self extractedBuilderWithParameters:parameters];
        if (builder.withKeyTypeEC) {
            SecKeyRef privateKeyRef = NULL;
            {
                // try decode by asn1 coder.
                NSError *theError = nil;
                NSArray *items = [[[JWT__ASN1__Coder alloc] parsedData:theData error:&theError] items];
                NSLog(@"items: %@", [items valueForKey:@"debugDescription"]);
            }
//            {
//                // try decode.
//                NSData *privateKeyData = [JWTCryptoSecurity__ASN1__Coder decodedItemsFromData:theData isPublic:NO error:nil][[JWTCryptoSecurity__ASN1__Coder parametersKeyPrivateKeyData]];
//                NSError *thisError = nil;
//                SecKeyRef ref = NULL;
//                if (privateKeyData) {
//                    ref = [JWTCryptoSecurity addKeyWithData:privateKeyData asPublic:NO tag:self.tag type:[self extractedSecKeyTypeWithParameters:parameters] error:&thisError];
//                }
//                if (!thisError && ref) {
//                    // ok!
//                    privateKeyRef = ref;
//                    theData = privateKeyData;
//                }
//                NSLog(@"thisError: %@ SecKeyRef: %@", thisError, ref);
//            }
            // cheat and shit!
            // ahaha. try to find correct key here.
            // possible soultion - dataByExtracting in cryptoKeySecurity.
            if (!privateKeyRef) {
                theData = [JWTCryptoSecurity dataByExtractingPrivateKeyFromANS1:theData error:nil];
                BOOL startFound = NO;
                while (theData != nil && theData.length > 0) {
                    NSError *theError = nil;
                    self.key = [JWTCryptoSecurity addKeyWithData:theData asPublic:NO tag:self.tag type:[self extractedSecKeyTypeWithParameters:parameters] error:&theError];
                    NSLog(@"theData: %@", theData);
                    NSLog(@"theError: %@", theError);
                    if (!theError && self.key) {
                        NSLog(@"Found!");
                        NSLog(@"theData: %@", theData);
                        NSLog(@"theKey: %@", self.key);
                        startFound = YES;
                        // try to cut down the size from back.
                        break;
                    }
                    if (!startFound) {
                        NSUInteger length = theData.length - 1;
                        NSRange range = NSMakeRange(1, length);
                        theData = [NSData dataWithBytes:((char *)theData.bytes) + range.location length:range.length];
                    }
                    else {
                        NSUInteger length = theData.length - 1;
                        NSRange range = NSMakeRange(0, length);
                        theData = [NSData dataWithBytes:((char *)theData.bytes) + range.location length:range.length];
                    }
                }
            }
        }
        
        self.key = [JWTCryptoSecurity addKeyWithData:theData asPublic:NO tag:self.tag type:[self extractedSecKeyTypeWithParameters:parameters] error:&addKeyError];
        if (!self.key || addKeyError) {
            if (error && addKeyError) {
                *error = addKeyError;
            }
            [self cleanup];
            return nil;
        }
    }
    return self;
}
// Exists
- (instancetype)initWithP12AtURL:(NSURL *)url withPassphrase:(NSString *)passphrase parameters:(NSDictionary *)parameters error:(NSError *__autoreleasing*)error {
    // take data.
    // cleanup if needed.
    NSData *data = [NSData dataWithContentsOfURL:url];
    return [self initWithP12Data:data withPassphrase:passphrase parameters:parameters error:error];
}
- (instancetype)initWithP12Data:(NSData *)p12Data withPassphrase:(NSString *)passphrase parameters:(NSDictionary *)parameters error:(NSError *__autoreleasing*)error {
    if (p12Data == nil) {
        return nil;
    }

    // cleanup if needed.
    SecIdentityRef identity = nil;
    SecTrustRef trust = nil;
    [JWTCryptoSecurity extractIdentityAndTrustFromPKCS12:(__bridge CFDataRef)p12Data password:(__bridge CFStringRef)passphrase identity:&identity trust:&trust];
    BOOL identityAndTrust = identity && trust;

    if (identityAndTrust) {
        self = [super init];
        SecKeyRef privateKey;
        SecIdentityCopyPrivateKey(identity, &privateKey);
        if (self) {
            self.key = privateKey;
        }
    }

    if (identity) {
        CFRelease(identity);
    }

    if (trust) {
        CFRelease(trust);
    }

    if (!identityAndTrust) {
        //error: no identity and trust.
        return nil;
    }

    return self;
}
@end
