# BouncyCastle-ObjC

<!--[![CI Status](https://img.shields.io/travis/CMK/BouncyCastle-ObjC.svg?style=flat)](https://travis-ci.org/CMK/BouncyCastle-ObjC)
[![Version](https://img.shields.io/cocoapods/v/BouncyCastle-ObjC.svg?style=flat)](https://cocoapods.org/pods/BouncyCastle-ObjC)
[![License](https://img.shields.io/cocoapods/l/BouncyCastle-ObjC.svg?style=flat)](https://cocoapods.org/pods/BouncyCastle-ObjC)
[![Platform](https://img.shields.io/cocoapods/p/BouncyCastle-ObjC.svg?style=flat)](https://cocoapods.org/pods/BouncyCastle-ObjC)-->

<!--## Example

To run the example project, clone the repo, and run `pod install` from the Example directory first.-->

## Requirements
- JDK 1.8 / 11

For example, use Homebrew to install the JDK 1.8

```bash
% brew install openjdk@8
% sudo ln -sfn /usr/local/opt/openjdk@8/libexec/openjdk.jdk /Library/Java/JavaVirtualMachines/openjdk-8.jdk
% echo $JAVA_HOME
> /Library/Java/JavaVirtualMachines/openjdk-8.jdk/Contents/Home

% java -version
> openjdk version "1.8.0_275"
> OpenJDK Runtime Environment (build 1.8.0_275-bre_2020_11_16_16_29-b00)
> OpenJDK 64-Bit Server VM (build 25.275-b00, mixed mode)
```


## Installation

BouncyCastle-ObjC is available through [CocoaPods](https://cocoapods.org). To install
it, simply add the following line to your Podfile:

```ruby
% pod 'BouncyCastle-ObjC'
```

## Troubleshoots

#### 1. J2ObjC dist/ folder is generated but no translated Objective-C files under Classes/. 

Please clean the Pods/ and use the `pod install --verbose`, make sure the `generate.sh` works without any error. After transalted job done you can run `pod install` again to generate valid xcworkspace.

## License

BouncyCastle-ObjC is available under the AGPL license. See the [LICENSE](https://github.com/DimensionDev/BouncyCastle-ObjC/blob/master/LICENSE) file for more info. The Bouncy Castle source code is licensed under [MIT](http://www.bouncycastle.org/licence.html).

