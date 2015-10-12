//
//  NSString+JWT.h
//  JWT
//
//  Created by Lobanov Dmitry on 07.10.15.
//  Copyright © 2015 Karma. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSString (JWT)

@property (nonatomic, readonly) NSString *base64UrlEncodedString;

+ (NSString *)base64UrlEncodedStringFromBase64String:(NSString *)base64String;

@end
