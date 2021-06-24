#include <vector>

#include "envoy/extensions/filters/http/ext_proc/v3alpha/ext_proc.pb.h"
#include "envoy/service/ext_proc/v3alpha/external_processor.pb.h"

#include "source/common/network/address_impl.h"

#include "test/common/http/common.h"
#include "test/extensions/filters/http/ext_proc/test_processor.h"
#include "test/fuzz/fuzz_runner.h"
#include "test/integration/http_integration.h"
#include "test/test_common/utility.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ExternalProcessing {

using envoy::extensions::filters::http::ext_proc::v3alpha::ProcessingMode;
using envoy::service::ext_proc::v3alpha::ProcessingRequest;
using envoy::service::ext_proc::v3alpha::ProcessingResponse;

using Http::LowerCaseString;

// The buffer size for the listeners
static const uint32_t BufferSize = 100000;

// These tests exercise ext_proc using the integration test framework and a real gRPC server
// for the external processor. This lets us more fully exercise all the things that happen
// with larger, streamed payloads.
class StreamingIntegrationFuzz : public HttpIntegrationTest,
                                 public Grpc::BaseGrpcClientIntegrationParamTest {

public:
  StreamingIntegrationFuzz(Network::Address::IpVersion ipVersion, Grpc::ClientType clientType)
      : HttpIntegrationTest(Http::CodecType::HTTP2, ipVersion) {
    ipVersion_ = ipVersion;
    clientType_ = clientType;
  }

  void sendData(Http::RequestEncoder& encoder, Buffer::Instance& data, bool end_stream) {
    codec_client_->sendData(encoder, data, end_stream);
  }

  void TearDown() {
    cleanupUpstreamAndDownstream();
    test_processor_.shutdown();
  }

  Network::Address::IpVersion ipVersion() const override { return ipVersion_; }
  Grpc::ClientType clientType() const override { return clientType_; }

  void initializeFuzzTest() {
    HttpIntegrationTest::initialize();
  }

  void initializeConfig() {
    // This enables a built-in automatic upstream server.
    autonomous_upstream_ = true;

    config_helper_.addConfigModifier([this](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
      // Create a cluster for our gRPC server pointing to the address that is running the gRPC
      // server.
      auto* processor_cluster = bootstrap.mutable_static_resources()->add_clusters();
      processor_cluster->set_name("ext_proc_server");
      processor_cluster->mutable_load_assignment()->set_cluster_name("ext_proc_server");
      auto* address = processor_cluster->mutable_load_assignment()
                          ->add_endpoints()
                          ->add_lb_endpoints()
                          ->mutable_endpoint()
                          ->mutable_address()
                          ->mutable_socket_address();
      address->set_address("127.0.0.1");
      address->set_port_value(test_processor_.port());

      // Ensure "HTTP2 with no prior knowledge." Necessary for gRPC.
      ConfigHelper::setHttp2(
          *(bootstrap.mutable_static_resources()->mutable_clusters()->Mutable(0)));
      ConfigHelper::setHttp2(*processor_cluster);

      // Make sure both flavors of gRPC client use the right address.
      const auto addr =
          std::make_shared<Network::Address::Ipv4Instance>("127.0.0.1", test_processor_.port());
      setGrpcService(*proto_config_.mutable_grpc_service(), "ext_proc_server", addr);

      // Merge the filter.
      envoy::config::listener::v3::Filter ext_proc_filter;
      ext_proc_filter.set_name("envoy.filters.http.ext_proc");
      ext_proc_filter.mutable_typed_config()->PackFrom(proto_config_);
      config_helper_.addFilter(MessageUtil::getJsonStringFromMessageOrDie(ext_proc_filter));
    });

    // Make sure that we have control over when buffers will fill up.
    config_helper_.setBufferLimits(BufferSize, BufferSize);

    setUpstreamProtocol(Http::CodecType::HTTP2);
    setDownstreamProtocol(Http::CodecType::HTTP2);
  }

  Http::RequestEncoder&
  sendClientRequestHeaders(absl::optional<std::function<void(Http::HeaderMap&)>> cb) {
    auto conn = makeClientConnection(lookupPort("http"));
    codec_client_ = makeHttpConnection(std::move(conn));
    Http::TestRequestHeaderMapImpl headers;
    HttpTestUtility::addDefaultHeaders(headers, std::string("POST"));
    if (cb) {
      (*cb)(headers);
    }
    auto encoder_decoder = codec_client_->startRequest(headers);
    client_response_ = std::move(encoder_decoder.second);
    return encoder_decoder.first;
  }

  void sendGetRequest(const Http::RequestHeaderMap& headers) {
    auto conn = makeClientConnection(lookupPort("http"));
    codec_client_ = makeHttpConnection(std::move(conn));
    client_response_ = codec_client_->makeHeaderOnlyRequest(headers);
  }

  TestProcessor test_processor_;
  envoy::extensions::filters::http::ext_proc::v3alpha::ExternalProcessor proto_config_{};
  IntegrationStreamDecoderPtr client_response_;
  Network::Address::IpVersion ipVersion_;
  Grpc::ClientType clientType_;
};

DEFINE_FUZZER(const uint8_t* buf, size_t len) {
  FuzzedDataProvider provider(buf, len);
  bool bufferedMode = false;  // TODO change this based on input

  // First byte determines number of chunks (e.g., [0, 255])
  // The remaining buffer bytes will be converted into 16 bit unsigned ints
  // determining the size of each chunk. If there are not remaining bytes,
  // update the number of chunks to match the remaining bytes.
  uint32_t num_chunks = static_cast<int32_t>(provider.ConsumeIntegral<uint8_t>());
  if (num_chunks > provider.remaining_bytes()/2) {
    num_chunks = provider.remaining_bytes() / 2;
  }

  // Calculate the total request size while parsing the size for each chunk, we
  // need the request size up front to set the header.
  uint32_t request_size = 0;
  std::vector<uint32_t> chunk_sizes;
  for (uint32_t i = 0; i < num_chunks; i++) {
    uint32_t tmp = static_cast<uint32_t>(provider.ConsumeIntegral<uint16_t>());
    chunk_sizes.push_back(tmp);
    request_size += tmp;
  }
  ENVOY_LOG_MISC(trace, "Request Size: {}", request_size);

  StreamingIntegrationFuzz fuzzer(Network::Address::IpVersion::v4, Grpc::ClientType::GoogleGrpc);

  // This starts the gRPC server in the background. It'll be shut down when we stop the tests.
  fuzzer.test_processor_.start(
      [bufferedMode](grpc::ServerReaderWriter<ProcessingResponse, ProcessingRequest>* stream) {
        ProcessingRequest header_req;
        if (!stream->Read(&header_req)) {
          return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "expected message");
        }
        if (!header_req.has_request_headers()) {
          return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "expected request headers");
        }

        if (bufferedMode) {
          // TODO send override message to enable buffered processing mode
        }
        ProcessingResponse header_resp;
        header_resp.mutable_request_headers();
        stream->Write(header_resp);
        return grpc::Status::OK;
      });

  ENVOY_LOG_MISC(trace, "External Process started.");

  fuzzer.initializeConfig();
  fuzzer.initializeFuzzTest();
  ENVOY_LOG_MISC(trace, "Fuzzer initialized");

  auto& encoder = fuzzer.sendClientRequestHeaders([request_size](Http::HeaderMap& headers) {
    headers.addCopy(LowerCaseString("expect_request_size_bytes"), request_size);
  });

  for (auto it = chunk_sizes.begin(); it != chunk_sizes.end(); ++it) {
    Buffer::OwnedImpl chunk;
    uint32_t chunk_size = *it;
    TestUtility::feedBufferWithRandomCharacters(chunk, chunk_size);
    fuzzer.sendData(encoder, chunk, false);
    ENVOY_LOG_MISC(trace, "Sending Chunk: {}", chunk_size);
  }
  Buffer::OwnedImpl empty_chunk;
  fuzzer.sendData(encoder, empty_chunk, true);

  ASSERT_TRUE(fuzzer.client_response_->waitForEndStream());
  EXPECT_TRUE(fuzzer.client_response_->complete());
  if (bufferedMode && request_size > BufferSize) {
    // If buffered processing is enabled and the request is larger than the
    // buffer size, the filter should have responded with HTTP 413
    ENVOY_LOG_MISC(trace, "Buffered Processing mode is on and sent too much data, expect 413.");
    EXPECT_THAT(fuzzer.client_response_->headers(), Http::HttpStatusIs("413"));
  } else {
    ENVOY_LOG_MISC(trace, "Buffered Processing mode is off or sent under limit, expect 200");
    EXPECT_THAT(fuzzer.client_response_->headers(), Http::HttpStatusIs("200"));
  }
  fuzzer.TearDown();
}

} // namespace ExternalProcessing
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
