//
//  JWT_ASN1_Coding.h
//  Base64
//
//  Created by Lobanov Dmitry on 18.03.2018.
//

#import <Foundation/Foundation.h>

@interface JWT_ASN1_Coding : NSObject

@end

@interface JWTCryptoSecurity__ASN1__Coder : NSObject
@property (copy, nonatomic, readonly, class) NSString *parametersKeyPrivateKeyData;
@property (copy, nonatomic, readonly, class) NSString *parametersKeyPublicKeyData;
//+ (NSDictionary *)decodedItemsFromData:(NSData *)data error:(NSError *__autoreleasing*)error;
+ (NSDictionary *)decodedItemsFromData:(NSData *)data isPublic:(BOOL)isPublic error:(NSError *__autoreleasing*)error;
@end

@protocol JWT__ASN1__Coder__Entry__Protocol <NSObject>
@property (copy, nonatomic, readonly) NSNumber *type; // the type of item

// should be filled by parsing.
//@property (copy, nonatomic, readonly) NSArray *children; // children of property. could be nil

// all data properties are accessed via ranges.
@property (assign, nonatomic, readonly) NSRange metadataRange; // type byte and length byte ( all special bytes also ).
@property (assign, nonatomic, readonly) NSRange itemRange; // or item range.
@property (assign, nonatomic, readonly) NSRange childrenRange; // children range.

// computed also by metadata range and data range.
//@property (assign, nonatomic, readonly) NSRange wholeRange;

// computed by ranges.
//@property (copy, nonatomic, readonly) NSData *entryData; // metadata specific for current item
//@property (copy, nonatomic, readonly) NSData *childrenData; // includes children
//@property (copy, nonatomic, readonly) NSData *wholeData; // includes metadata and data
@end

// and also add enum for typeInt
@interface JWT__ASN1__Coder__Entry : NSObject <JWT__ASN1__Coder__Entry__Protocol> @end

@interface JWT__ASN1__Coder : NSObject
@property (copy, nonatomic, readonly) NSData *data;
@property (copy, nonatomic, readonly) NSArray<JWT__ASN1__Coder__Entry *> *items;
- (instancetype)parsedData:(NSData *)data error:(NSError *__autoreleasing *)error;
@end

@interface JWT__ASN1__Coder (Parse)
- (void)parseData:(NSData *)data error:(NSError *__autoreleasing *)error;
@end
