#import <Foundation/Foundation.h>
#import <Network/Network.h>

// Heavily inspired by TrustKit's test suite
#pragma mark Test NSURLSession delegate

@interface TestNSURLSessionDelegate : NSObject <NSURLSessionTaskDelegate, NSURLSessionDataDelegate>
{
}
@property NSError *lastError;
@property NSURLResponse *lastResponse;

@property BOOL wasAuthHandlerCalled; // Used to validate that the delegate's auth handler was called


- (void)URLSession:(NSURLSession * _Nonnull)session
              task:(NSURLSessionTask * _Nonnull)task
didCompleteWithError:(NSError * _Nullable)error;

- (void)URLSession:(NSURLSession * _Nonnull)session
          dataTask:(NSURLSessionDataTask * _Nonnull)dataTask
didReceiveResponse:(NSURLResponse * _Nonnull)response
 completionHandler:(void (^ _Nonnull)(NSURLSessionResponseDisposition disposition))completionHandler;

- (void)URLSession:(NSURLSession * _Nonnull)session
              task:(NSURLSessionTask * _Nonnull)task
didReceiveChallenge:(NSURLAuthenticationChallenge * _Nonnull)challenge
 completionHandler:(void (^ _Nonnull)(NSURLSessionAuthChallengeDisposition disposition,
                                      NSURLCredential * _Nullable credential))completionHandler;

@end


@implementation TestNSURLSessionDelegate

- (void)URLSession:(NSURLSession * _Nonnull)session
              task:(NSURLSessionTask * _Nonnull)task
didCompleteWithError:(NSError * _Nullable)error
{
    NSLog(@"Received error, %@", error);
    _lastError = error;
    NSLog(@"Expectation fulfilled (didCompleteWithError)!");
}

- (void)URLSession:(NSURLSession * _Nonnull)session
          dataTask:(NSURLSessionDataTask * _Nonnull)dataTask
didReceiveResponse:(NSURLResponse * _Nonnull)response
 completionHandler:(void (^ _Nonnull)(NSURLSessionResponseDisposition disposition))completionHandler
{
    _lastResponse = response;
    NSLog(@"Expectation fulfilled (didReceiveResponse)!");
}

- (void)URLSession:(NSURLSession * _Nonnull)session
              task:(NSURLSessionTask * _Nonnull)task
didReceiveChallenge:(NSURLAuthenticationChallenge * _Nonnull)challenge
 completionHandler:(void (^ _Nonnull)(NSURLSessionAuthChallengeDisposition disposition,
                                      NSURLCredential * _Nullable credential))completionHandler
{
    // Reject all certificates; this replicates what would happen when pinning validation would fail due to traffic interception
    completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
}


@end


#pragma mark Test suite
@interface SKSEndToEndNSURLSessionTests : NSObject

@end

@implementation SKSEndToEndNSURLSessionTests

- (void)setUp {
    [[NSURLCache sharedURLCache] removeAllCachedResponses];
}

- (void)tearDown {
}

- (void)test
{    
    TestNSURLSessionDelegate* delegate = [[TestNSURLSessionDelegate alloc] init];
    
    NSURLSession *session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration]
                                                          delegate:delegate
                                                     delegateQueue:nil];
    
    NSURLSessionDataTask *task = [session dataTaskWithURL:[NSURL URLWithString:@"https://www.google.com/"]];
    [task resume];
    
    // Wait for the connection to succeed
    usleep(5000000);

    if (!delegate.lastResponse) {
        NSLog(@"FAIL: TLS certificate was rejected although all TLS validation was disabled");
        exit(1);
    }
    if (!!delegate.lastError) {
        NSLog(@"FAIL: TLS certificate was rejected although all TLS validation was disabled");
        exit(1);
    }
}

@end

int main() {
    SKSEndToEndNSURLSessionTests *t = [[SKSEndToEndNSURLSessionTests alloc] init];
    [t setUp];
    [t test];
    [t tearDown];
    return 0;
}
