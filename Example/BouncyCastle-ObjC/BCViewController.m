//
//  BCViewController.m
//  BouncyCastle-ObjC
//
//  Created by CMK on 05/30/2019.
//  Copyright (c) 2019 CMK. All rights reserved.
//

#import "BCViewController.h"
@import BouncyCastle_ObjC;
@import JRE.java.util;

@interface BCViewController ()

@end

@implementation BCViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
	// Do any additional setup after loading the view, typically from a nib.
    NSString *time = [[[JavaUtilDate alloc] init] toGMTString];
    NSLog(@"JavaUtilDate.toGMTString is: %@", time);
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
