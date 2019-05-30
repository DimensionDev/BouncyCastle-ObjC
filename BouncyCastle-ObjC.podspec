#
# Be sure to run `pod lib lint BouncyCastle-ObjC.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see https://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = 'BouncyCastle-ObjC'
  s.version          = '0.1.0'
  s.summary          = 'Objective-C Bouncy Castle.'

# This description is used to generate tags and improve search results.
#   * Think: What does it do? Why did you write it? What is the focus?
#   * Try to keep it short, snappy and to the point.
#   * Write the description between the DESC delimiters below.
#   * Finally, don't worry about the indent, CocoaPods strips it!

  s.description      = <<-DESC
Objective-C Bouncy Castle converted from Java implement use J2ObjC. 
                       DESC

  s.homepage         = 'https://github.com/DimensionDev/BouncyCastle-ObjC'
  s.license          = { :type => 'AGPL', :file => 'LICENSE' }
  s.author           = { 'CMK' => 'cirno.mainasuk@gmail.com' }
  s.source           = { :git => 'https://github.com/DimensionDev/BouncyCastle-ObjC.git', :tag => s.version.to_s }

  s.prepare_command = <<-CMD
    BouncyCastle-ObjC/Scripts/download.sh
    BouncyCastle-ObjC/Scripts/generate.sh
  CMD

  s.ios.deployment_target = '8.0'
  s.requires_arc = false

  s.preserve_paths = 'dist/**/*', 'BouncyCastle-ObjC/**/*'
  s.source_files = 'BouncyCastle-ObjC/Classes/**/*'
  
  s.xcconfig = { 
    'LIBRARY_SEARCH_PATHS' => '"${PODS_ROOT}/BouncyCastle-ObjC/dist/lib"',
    'HEADER_SEARCH_PATHS' => '"${PODS_ROOT}/BouncyCastle-ObjC/dist/frameworks/JRE.framework/Headers"',
  }

  s.libraries = 'jre_emul', 'z', 'iconv'
  # enable static framework due to we use .a
  s.static_framework = true
  
  # s.resource_bundles = {
  #   'BouncyCastle-ObjC' => ['BouncyCastle-ObjC/Assets/*.png']
  # }

  # s.public_header_files = 'Pod/Classes/**/*.h'
  # s.frameworks = 'UIKit', 'MapKit'
  # s.dependency 'AFNetworking', '~> 2.3'
end
