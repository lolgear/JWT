//
//  JWT_ASN1_Coding.m
//  Base64
//
//  Created by Lobanov Dmitry on 18.03.2018.
//

#import "JWT_ASN1_Coding.h"

@implementation JWT_ASN1_Coding

@end

#import <Security/SecAsn1Coder.h>
#import <Security/SecAsn1Templates.h>
#import <Security/SecAsn1Types.h>

/* AlgorithmIdentifier : SecAsn1AlgId */
const SecAsn1Template kSecAsn1AlgorithmIDTemplate[] = {
    { SEC_ASN1_SEQUENCE,
        0, NULL, sizeof(SecAsn1AlgId) },
    { SEC_ASN1_OBJECT_ID,
        offsetof(SecAsn1AlgId,algorithm), },
    { SEC_ASN1_OPTIONAL | SEC_ASN1_ANY,
        offsetof(SecAsn1AlgId,parameters), },
    { 0, }
};

/* SubjectPublicKeyInfo : SecAsn1PubKeyInfo */
const SecAsn1Template kSecAsn1SubjectPublicKeyInfoTemplate[] = {
    { SEC_ASN1_SEQUENCE,
        0, NULL, sizeof(SecAsn1PubKeyInfo) },
    { SEC_ASN1_INLINE,
        offsetof(SecAsn1PubKeyInfo,algorithm),
        kSecAsn1AlgorithmIDTemplate },
    { SEC_ASN1_BIT_STRING,
        offsetof(SecAsn1PubKeyInfo,subjectPublicKey), },
    { 0, }
};

typedef struct {
    SecAsn1Item        version;
    SecAsn1Item        privateKey;
    SecAsn1Item        params;        /* optional, ANY */
    SecAsn1Item        pubKey;        /* BITSTRING, optional */
} JWT_ECDSA_PrivateKey;

const SecAsn1Template kSecAsn1ECDSAPrivateKeyInfoTemplate[] = {
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(JWT_ECDSA_PrivateKey) },
    { SEC_ASN1_INTEGER, offsetof(JWT_ECDSA_PrivateKey,version) },
    { SEC_ASN1_OCTET_STRING, offsetof(JWT_ECDSA_PrivateKey,privateKey) },
    { SEC_ASN1_OPTIONAL | SEC_ASN1_CONSTRUCTED | SEC_ASN1_EXPLICIT | SEC_ASN1_CONTEXT_SPECIFIC | 0,
        offsetof(JWT_ECDSA_PrivateKey,params), kSecAsn1AnyTemplate},
    { SEC_ASN1_OPTIONAL | SEC_ASN1_CONSTRUCTED | SEC_ASN1_EXPLICIT | SEC_ASN1_CONTEXT_SPECIFIC | 1,
        offsetof(JWT_ECDSA_PrivateKey,pubKey), kSecAsn1BitStringTemplate },
    { 0, }
};

typedef struct {
    SecAsn1Item version;
    SecAsn1AlgId algorithm;
    JWT_ECDSA_PrivateKey privateKey;
} JWT_ECDSA_SubjectPrivateKey;

const SecAsn1Template kSecAsn1SubjectPrivateKeyInfoTemplate[] = {
    { SEC_ASN1_SEQUENCE,
        0, NULL, sizeof(JWT_ECDSA_SubjectPrivateKey) },
    { SEC_ASN1_INLINE,
        offsetof(JWT_ECDSA_SubjectPrivateKey, algorithm),
        kSecAsn1AlgorithmIDTemplate },
    { SEC_ASN1_OCTET_STRING, offsetof(JWT_ECDSA_SubjectPrivateKey, privateKey), kSecAsn1ECDSAPrivateKeyInfoTemplate},
    { 0, }
};

@implementation JWTCryptoSecurity__ASN1__Coder

// good exapmle.
//typedef struct {
//    size_t          length;
//    unsigned char   *data;
//} ASN1_Data;
//
//typedef struct {
//    ASN1_Data type;     // INTEGER
//    ASN1_Data version;  // INTEGER
//    ASN1_Data value;    // OCTET STRING
//} RVNReceiptAttribute;
//
//typedef struct {
//    RVNReceiptAttribute **attrs;
//} RVNReceiptPayload;
//
//// ASN.1 receipt attribute template
//static const SecAsn1Template kReceiptAttributeTemplate[] = {
//    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(RVNReceiptAttribute) },
//    { SEC_ASN1_INTEGER, offsetof(RVNReceiptAttribute, type), NULL, 0 },
//    { SEC_ASN1_INTEGER, offsetof(RVNReceiptAttribute, version), NULL, 0 },
//    { SEC_ASN1_OCTET_STRING, offsetof(RVNReceiptAttribute, value), NULL, 0 },
//    { 0, 0, NULL, 0 }
//};
//
//// ASN.1 receipt template set
//static const SecAsn1Template kSetOfReceiptAttributeTemplate[] = {
//    { SEC_ASN1_SET_OF, 0, kReceiptAttributeTemplate, sizeof(RVNReceiptPayload) },
//    { 0, 0, NULL, 0 }
//};

+ (NSString *)parametersKeyPrivateKeyData {
    return NSStringFromSelector(_cmd);
}
+ (NSString *)parametersKeyPublicKeyData {
    return NSStringFromSelector(_cmd);
}
+ (NSData *)dataFromASN1Data:(CSSM_DATA)asn1 maxLength:(CSSM_SIZE)length {
    if (asn1.Length == 0) {
        return nil;
    }
    return [NSData dataWithBytes:asn1.Data length:MIN(asn1.Length, length)];
}
+ (NSData *)dataFromASN1Data:(CSSM_DATA)asn1 {
    if (asn1.Length == 0) {
        return nil;
    }
    return [NSData dataWithBytes:asn1.Data length:asn1.Length];
}
+ (NSData *)publicKeyFromASN1:(CSSM_DATA)asn1 {
    // subject is bit string
    // last index here is:
    size_t scale = CHAR_BIT; // count of bits in byte.
    size_t newLength = asn1.Length / scale;
    NSData *data = [self dataFromASN1Data:asn1 maxLength:newLength];
    return data;
}
+ (NSData *)publicKeyFromASN1PublicKey:(SecAsn1PubKeyInfo)asn1 {
    NSData *data = [self publicKeyFromASN1:asn1.subjectPublicKey];
    return data;
}
+ (NSData *)publicKeyFromASN1PrivateKey:(JWT_ECDSA_PrivateKey)asn1 {
    return [self publicKeyFromASN1:asn1.pubKey];
}
+ (NSData *)privateKeyFromASN1PrivateKey:(JWT_ECDSA_PrivateKey)asn1 {
    return [self dataFromASN1Data:asn1.privateKey];
}
//+ (NSData *)privateKeyFromANS1:(SecAsn1PubKeyInfo)asn1 {
//    // a bit harder!
//    //
//    NSData *parameters = [self dataFromASN1Data:asn1.algorithm.parameters];
//    NSData *algorithm = [self dataFromASN1Data:asn1.algorithm.algorithm];
//    NSMutableData *result = [[NSData data] mutableCopy];
//    if (!parameters || !algorithm) {
//        return nil;
//    }
//    [result appendData:parameters];
//    [result appendData:algorithm];
//    return result;
//}
+ (NSDictionary *)decodedItemsFromData:(NSData *)data isPublic:(BOOL)isPublic error:(NSError *__autoreleasing*)error {
    if (data == nil) {
        return nil;
    }
    SecAsn1CoderRef coder = NULL;
    OSStatus status = SecAsn1CoderCreate(&coder);
    if (status != errSecSuccess) {
        if (error) {
            *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
        }
        return nil;
    }

    NSData *publicKeyData = nil;
    NSData *privateKeyData = nil;
    NSError *decodeError = nil;

    NSLog(@"parse data: %@", data);

    if (isPublic) {
        SecAsn1PubKeyInfo info = { 0 };
        OSStatus status = SecAsn1Decode(coder, data.bytes, data.length, kSecAsn1SubjectPublicKeyInfoTemplate, &info);
        decodeError = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
        if (decodeError.code == errSecSuccess) {
            publicKeyData = [self publicKeyFromASN1PublicKey:info];
        }
    }
    else {
        JWT_ECDSA_PrivateKey info = { 0 };
        OSStatus status = SecAsn1Decode(coder, data.bytes, data.length, kSecAsn1ECDSAPrivateKeyInfoTemplate, &info);
        decodeError = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
        if (decodeError.code == errSecSuccess) {
            publicKeyData = [self publicKeyFromASN1PrivateKey:info];
            privateKeyData = [self privateKeyFromASN1PrivateKey:info];
        }
    }

    if (decodeError.code == errSecSuccess) {
        NSMutableDictionary *result = [@{} mutableCopy];
        if (publicKeyData) {
            result[self.parametersKeyPublicKeyData] = publicKeyData;
        }
        if (privateKeyData) {
            result[self.parametersKeyPrivateKeyData] = privateKeyData;
        }
        NSLog(@"result: %@", result);
        return result;
    }

    if (decodeError.code != errSecSuccess) {
        if (decodeError.code == errSecDecode) {
            NSLog(@"Not decoded! %@", decodeError);
        }
        NSLog(@"error: %@", decodeError);
        if (error) {
            *error = decodeError;
        }
    }
    return nil;
}

@end

typedef NS_ENUM(NSInteger, JWT__ASN1__Entry__Type) {
    JWT__ASN1__Entry__Type__BOOLEAN           = 0x01,
    JWT__ASN1__Entry__Type__INTEGER           = 0x02,
    JWT__ASN1__Entry__Type__BIT_STRING        = 0x03,
    JWT__ASN1__Entry__Type__OCTET_STRING      = 0x04,
    JWT__ASN1__Entry__Type__NULL              = 0x05,
    JWT__ASN1__Entry__Type__OBJECT_ID         = 0x06,
    JWT__ASN1__Entry__Type__OBJECT_DESCRIPTOR = 0x07,
    /* External type and instance-of type   0x08 */
    JWT__ASN1__Entry__Type__REAL              = 0x09,
    JWT__ASN1__Entry__Type__ENUMERATED        = 0x0a,
    JWT__ASN1__Entry__Type__EMBEDDED_PDV      = 0x0b,
    JWT__ASN1__Entry__Type__UTF8_STRING       = 0x0c,
    /* not used                         0x0d */
    /* not used                         0x0e */
    /* not used                         0x0f */
    JWT__ASN1__Entry__Type__SEQUENCE          = 0x10,

    // additional
    JWT__ASN1__Entry__Type__CONSTRUCTED       = 0x20,
//    JWT__ASN1__Entry__Type__GROUP             = 0x02000,
//    JWT__ASN1__Entry__Type__SEQUENCE__OF      = JWT__ASN1__Entry__Type__SEQUENCE | JWT__ASN1__Entry__Type__GROUP,
    JWT__ASN1__Entry__Type__SEQUENCE__CONSTRUCTED = JWT__ASN1__Entry__Type__SEQUENCE | JWT__ASN1__Entry__Type__CONSTRUCTED

};

@interface JWT__ASN1__Coder__Entry__Type__Description : NSObject
+ (NSDictionary *)items;
+ (NSString *)stringForItem:(JWT__ASN1__Entry__Type)item;
@end

@implementation JWT__ASN1__Coder__Entry__Type__Description
+ (NSDictionary *)items {
    static NSDictionary *dictionary = nil;
    return dictionary ?: (dictionary = @{
                                         @(JWT__ASN1__Entry__Type__BOOLEAN) : @"JWT__ASN1__Entry__Type__BOOLEAN",
                                         @(JWT__ASN1__Entry__Type__INTEGER) : @"JWT__ASN1__Entry__Type__INTEGER",
                                         @(JWT__ASN1__Entry__Type__BIT_STRING) : @"JWT__ASN1__Entry__Type__BIT_STRING",
                                         @(JWT__ASN1__Entry__Type__OCTET_STRING) : @"JWT__ASN1__Entry__Type__OCTET_STRING",
                                         @(JWT__ASN1__Entry__Type__NULL) : @"JWT__ASN1__Entry__Type__NULL",
                                         @(JWT__ASN1__Entry__Type__OBJECT_ID) : @"JWT__ASN1__Entry__Type__OBJECT_ID",
                                         @(JWT__ASN1__Entry__Type__OBJECT_DESCRIPTOR) : @"JWT__ASN1__Entry__Type__OBJECT_DESCRIPTOR",
                                         @(JWT__ASN1__Entry__Type__REAL) : @"JWT__ASN1__Entry__Type__REAL",
                                         @(JWT__ASN1__Entry__Type__ENUMERATED) : @"JWT__ASN1__Entry__Type__ENUMERATED",
                                         @(JWT__ASN1__Entry__Type__EMBEDDED_PDV) : @"JWT__ASN1__Entry__Type__EMBEDDED_PDV",
                                         @(JWT__ASN1__Entry__Type__UTF8_STRING) : @"JWT__ASN1__Entry__Type__UTF8_STRING",
                                         @(JWT__ASN1__Entry__Type__SEQUENCE) : @"JWT__ASN1__Entry__Type__SEQUENCE",
                                         @(JWT__ASN1__Entry__Type__CONSTRUCTED) : @"JWT__ASN1__Entry__Type__CONSTRUCTED",
//                                         @(JWT__ASN1__Entry__Type__GROUP) : @"JWT__ASN1__Entry__Type__GROUP",
//                                         @(JWT__ASN1__Entry__Type__SEQUENCE__OF) : @"JWT__ASN1__Entry__Type__SEQUENCE__OF",
                                         @(JWT__ASN1__Entry__Type__SEQUENCE__CONSTRUCTED) : @"JWT__ASN1__Entry__Type__SEQUENCE__CONSTRUCTED"
                                         });
}
+ (NSString *)stringForItem:(JWT__ASN1__Entry__Type)item {
    return [self items][@(item)] ?: @"Unknown:JWT__ASN1__Entry_Type";
}
@end

@interface JWT__ASN1__Coder__Entry ()
@property (copy, nonatomic, readwrite) NSNumber *type; // the type of item
//@property (assign, nonatomic, readonly) NSRange metadataRange; // type byte and length byte ( all special bytes also ).
@property (assign, nonatomic, readwrite) NSRange itemRange; // or item range.
@property (assign, nonatomic, readwrite) NSRange childrenRange; // children range.
+ (instancetype)entryForType:(NSNumber *)type;
// count is not the same as Range.length!
- (instancetype)updatedItemRangeByRange:(NSRange)range andCount:(NSInteger)count;
+ (NSString *)stringForType:(NSNumber *)type;
@property (weak, nonatomic, readwrite) JWT__ASN1__Coder *coder;
@end

@interface JWT__ASN1__Coder__Entry (Accessors)
@property (assign, nonatomic, readonly) BOOL hasChildren;
@property (assign, nonatomic, readonly) NSUInteger border;
- (NSData *)dataAtRange:(NSRange)range;
@end

@implementation JWT__ASN1__Coder__Entry
//+ (NSDictionary *)entries {
//    return nil;
//}

+ (instancetype)entryForType:(NSNumber *)type {
    JWT__ASN1__Coder__Entry *entry = [self new];
    entry.type = type;
    return entry;
}

+ (NSString *)stringForType:(NSNumber *)type {
    return [JWT__ASN1__Coder__Entry__Type__Description stringForItem:type.integerValue];
}

- (instancetype)updatedItemRangeByRange:(NSRange)range andCount:(NSInteger)count {
    // ask if has children or not.
    if (self.hasChildren) {
        NSRange itemRange = (NSRange){range.location, 2};
        self.itemRange = itemRange;
        NSRange childrenRange = (NSRange){itemRange.location + itemRange.length, count};
        self.childrenRange = childrenRange;
    }
    else {
        self.itemRange = (NSRange){range.location, 2 + count};
    }

    return self;
}

- (NSRange)metadataRange {
    NSRange range = (NSRange){0,0};
    if (self.hasChildren) {
        range = self.itemRange;
    }
    else {
        range = (NSRange){self.itemRange.location, 2};
    }
    return range;
}

#pragma mark - NSObject
- (NSString *)debugDescription {
    return [[self debugInformation] description];
}

- (NSDictionary *)debugInformation {
    return @{
             @"type" : self.type ?: [NSNull null],
             @"typeDescription": [self.class stringForType:self.type],
             @"itemRange": [NSValue valueWithRange:self.itemRange],
             @"itemData": [self dataAtRange:self.itemRange] ?: [NSNull null],
             @"childrenRange" : [NSValue valueWithRange:self.childrenRange],
             @"childrenData" : [self dataAtRange:self.childrenRange] ?: [NSNull null],
             @"metadataRange" : [NSValue valueWithRange:self.metadataRange],
             @"metadataData" : [self dataAtRange:self.metadataRange] ?: [NSNull null]
             };
}
@end

@implementation JWT__ASN1__Coder__Entry (Accessors)
// determine by type.
- (BOOL)hasChildren {
    NSInteger value = self.type.integerValue;
    BOOL result =
    value == JWT__ASN1__Entry__Type__OCTET_STRING ||
    value == JWT__ASN1__Entry__Type__SEQUENCE ||
//    value == JWT__ASN1__Entry__Type__SEQUENCE__OF ||
    value == JWT__ASN1__Entry__Type__SEQUENCE__CONSTRUCTED;
    return result;
}
- (NSUInteger)border {
    return self.itemRange.location + self.itemRange.length;
}

- (NSData *)dataAtRange:(NSRange)range {
    return [self.coder.data subdataWithRange:range];
}
@end

@protocol JWT__ASN1__Coder__Helper
- (JWT__ASN1__Coder__Entry *)parseData:(NSData *)data inBounds:(NSRange)range error:(NSError *__autoreleasing *)error;
@end

// parse the header of the key.
@interface JWT__ASN1__Coder__Helper__Simple : NSObject @end
@interface JWT__ASN1__Coder__Helper__Premier : NSObject @end

@implementation JWT__ASN1__Coder__Helper__Simple
- (JWT__ASN1__Coder__Entry *)parseData:(NSData *)data inBounds:(NSRange)range error:(NSError *__autoreleasing *)error {
    // has children.
    // so, first, read item.
    // then, try to understand what to read.
    if (range.length < 2) {
        // raise error? or skip item.
        return nil;
    }

    UInt8 *bytes = (UInt8 *)data.bytes;

    NSInteger type = bytes[range.location];
    NSInteger length = bytes[range.location + 1];
    // next, read data which specified in length and put item range to it.
    JWT__ASN1__Coder__Entry *entry = [[JWT__ASN1__Coder__Entry entryForType:@(type)] updatedItemRangeByRange:range andCount:length];
    return entry;
}
@end

@implementation JWT__ASN1__Coder__Helper__Premier
- (JWT__ASN1__Coder__Entry *)parseData:(NSData *)data inBounds:(NSRange)range error:(NSError *__autoreleasing *)error {
    // try to understand type.
    // and next read a length of this type.
    // range length should be at least three bytes for item and length. ( Premier sequence )

    if (range.length < 3) {
        // raise error? or skip item.
        return nil;
    }

    UInt8 *bytes = (UInt8 *)data.bytes;

    NSInteger type = bytes[range.location];
    // now we could determine the type of item.
    // this type should be a sequence with second special byte.
    NSInteger specialByte = bytes[range.location + 1];
    // special byte could be greater than 80.
    // if so, it is special sequence with length at third byte.
    // specialByte
    BOOL hasSpecialByte = specialByte > 0x80;

    NSInteger length = hasSpecialByte ? bytes[range.location + 2] : specialByte;
    // next, we should determine borders and correct them for our range.
    // also we could check that
    JWT__ASN1__Coder__Entry *entry = [JWT__ASN1__Coder__Entry entryForType:@(type)];
    // this entry has children ( should have ), because it is Sequence ( or Octet string )
    // now we return it.
    // so, item range depends on length.

    entry.itemRange = (NSRange){range.location, 2 + hasSpecialByte};
    entry.childrenRange = (NSRange){entry.itemRange.location + entry.itemRange.length, length};
    return entry;
}
@end

@interface JWT__ASN1__Coder ()
@property (copy, nonatomic, readwrite) NSData *data;
@property (copy, nonatomic, readwrite) NSArray<JWT__ASN1__Coder__Entry *> *items;
@property (strong, nonatomic, readwrite) JWT__ASN1__Coder__Entry *parentEntry;
@end

@implementation JWT__ASN1__Coder
- (instancetype)parsedData:(NSData *)data error:(NSError *__autoreleasing *)error {
    if (!data) {
        if (error) {
            *error = [NSError errorWithDomain:@"io.domain" code:-100 userInfo:nil];
        }
        return self;
    }
    self.data = data;
    [self parseData:data error:error];
    return self;
}
@end

@implementation JWT__ASN1__Coder (Parse)
- (void)addItem:(JWT__ASN1__Coder__Entry *)item {
    if (item == nil) {
        // nil!
        return;
    }
    item.coder = self;
    NSLog(@"entry: %@", [item debugInformation]);
    self.items = [self.items ?: @[] arrayByAddingObject:item];
}

- (void)parseData:(NSData *)data error:(NSError *__autoreleasing *)error {
    self.data = data;
    JWT__ASN1__Coder__Entry *entry = [[JWT__ASN1__Coder__Helper__Premier new] parseData:data inBounds:NSMakeRange(0, data.length) error:error];

    if (entry) {
        // so, we could parse it.
        // put into items and start read.
        // assuming that entry is a Sequence.
        [self addItem:entry];
        int count = 5;
        while (entry != nil && (entry.border != data.length)) {
            //
            // calculate bounds.
            NSUInteger border = entry.border;
            NSRange bounds = (NSRange){border, data.length - border};
            entry = [[JWT__ASN1__Coder__Helper__Simple new] parseData:data inBounds:bounds error:error];
            [self addItem:entry];
            if (!count--) {
                break;
            }
        }
    }
}
@end
