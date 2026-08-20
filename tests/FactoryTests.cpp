#include "ZaphoydTppFactory.h"
#include "WebsocketEndPoint.h"
#include "WebsocketOptions.h"
#include "WebsocketState.h"
#include "support/LocalEchoServer.h"
#include "support/RecordingListener.h"
#include "support/TestBlob.h"
#include <gtest/gtest.h>
#include <memory>
#include <string>

namespace
{

class ZaphoydTppFactoryTest : public ::testing::Test
{
protected:
    void SetUp() override { _server.start(); }
    void TearDown() override { _server.stop(); }

    std::unique_ptr<Websocket::EndPoint> openEndpoint(
        const std::shared_ptr<Tests::RecordingListener>& listener) {
        auto endpoint = _factory.create();
        endpoint->setListener(listener);
        Websocket::Options options;
        options._host = _server.url();
        EXPECT_TRUE(endpoint->open(std::move(options)));
        EXPECT_TRUE(listener->waitForState(Websocket::State::Connected));
        return endpoint;
    }

    ZaphoydTppFactory _factory;
    Tests::LocalEchoServer _server;
};

} // namespace

TEST_F(ZaphoydTppFactoryTest, CreateProducesDistinctEndpoints)
{
    const auto ep1 = _factory.create();
    const auto ep2 = _factory.create();
    ASSERT_TRUE(ep1);
    ASSERT_TRUE(ep2);
    EXPECT_NE(ep1->id(), ep2->id());
}

TEST_F(ZaphoydTppFactoryTest, FreshEndpointIsDisconnectedAndInert)
{
    const auto endpoint = _factory.create();
    EXPECT_EQ(Websocket::State::Disconnected, endpoint->state());
    EXPECT_TRUE(endpoint->host().empty());
    EXPECT_FALSE(endpoint->sendText("hello"));
    EXPECT_FALSE(endpoint->sendBinary(Tests::TestBlob("hello")));
    EXPECT_FALSE(endpoint->ping());
    EXPECT_FALSE(endpoint->ping(Tests::TestBlob("ping")));
}

TEST_F(ZaphoydTppFactoryTest, OpenConnectsAndReachesConnectedState)
{
    const auto listener = std::make_shared<Tests::RecordingListener>();
    const auto endpoint = openEndpoint(listener);
    EXPECT_EQ(_server.url(), endpoint->host());
}

TEST_F(ZaphoydTppFactoryTest, TextMessageRoundTrips)
{
    const auto listener = std::make_shared<Tests::RecordingListener>();
    const auto endpoint = openEndpoint(listener);

    ASSERT_TRUE(endpoint->sendText("hello, world"));
    ASSERT_TRUE(listener->waitForTextMessages(1U));
    const auto messages = listener->textMessages();
    ASSERT_EQ(1U, messages.size());
    EXPECT_EQ("hello, world", messages.front());
}

TEST_F(ZaphoydTppFactoryTest, BinaryMessageRoundTripsAndDoesNotFireOnPong)
{
    // Regression test for the fixed onMessage() switch fallthrough: a binary
    // message must never also invoke onPong().
    const auto listener = std::make_shared<Tests::RecordingListener>();
    const auto endpoint = openEndpoint(listener);

    const std::string payload("binary-payload");
    ASSERT_TRUE(endpoint->sendBinary(Tests::TestBlob(payload)));
    ASSERT_TRUE(listener->waitForBinaryMessages(1U));

    const auto messages = listener->binaryMessages();
    ASSERT_EQ(1U, messages.size());
    EXPECT_EQ(payload, messages.front());
    EXPECT_EQ(0U, listener->pongCount());
}

TEST_F(ZaphoydTppFactoryTest, PingYieldsPong)
{
    const auto listener = std::make_shared<Tests::RecordingListener>();
    const auto endpoint = openEndpoint(listener);

    ASSERT_TRUE(endpoint->ping());
    ASSERT_TRUE(listener->waitForPongs(1U));

    ASSERT_TRUE(endpoint->ping(Tests::TestBlob("ping-payload")));
    ASSERT_TRUE(listener->waitForPongs(2U));
}

TEST_F(ZaphoydTppFactoryTest, CloseTransitionsToDisconnectedAndRejectsFurtherSends)
{
    const auto listener = std::make_shared<Tests::RecordingListener>();
    const auto endpoint = openEndpoint(listener);

    endpoint->close();
    ASSERT_TRUE(listener->waitForState(Websocket::State::Disconnected));

    EXPECT_FALSE(endpoint->sendText("after-close"));
    EXPECT_FALSE(endpoint->sendBinary(Tests::TestBlob("after-close")));
    EXPECT_FALSE(endpoint->ping());
    EXPECT_EQ(0U, listener->textMessages().size());
    EXPECT_EQ(0U, listener->binaryMessages().size());
}

TEST_F(ZaphoydTppFactoryTest, ReopenAfterCloseWorks)
{
    const auto listener1 = std::make_shared<Tests::RecordingListener>();
    const auto endpoint = openEndpoint(listener1);
    endpoint->close();
    ASSERT_TRUE(listener1->waitForState(Websocket::State::Disconnected));

    // fresh listener for the second connection cycle, for an unambiguous event log
    const auto listener2 = std::make_shared<Tests::RecordingListener>();
    endpoint->setListener(listener2);
    Websocket::Options options;
    options._host = _server.url();
    ASSERT_TRUE(endpoint->open(std::move(options)));
    ASSERT_TRUE(listener2->waitForState(Websocket::State::Connected));

    ASSERT_TRUE(endpoint->sendText("still-works"));
    ASSERT_TRUE(listener2->waitForTextMessages(1U));
    EXPECT_EQ("still-works", listener2->textMessages().front());
}

TEST_F(ZaphoydTppFactoryTest, ResetListenerStopsCallbacks)
{
    const auto listener = std::make_shared<Tests::RecordingListener>();
    const auto endpoint = openEndpoint(listener);

    endpoint->resetListener();
    // give any in-flight callback delivery a chance to (incorrectly) arrive
    ASSERT_TRUE(endpoint->sendText("should-not-be-observed"));
    EXPECT_FALSE(listener->waitForTextMessages(1U, std::chrono::milliseconds(500)));
    EXPECT_TRUE(listener->textMessages().empty());
}

TEST_F(ZaphoydTppFactoryTest, OpenWithInvalidHostFailsAndFiresOnError)
{
    const auto listener = std::make_shared<Tests::RecordingListener>();
    const auto endpoint = _factory.create();
    endpoint->setListener(listener);

    Websocket::Options options; // empty/default _host is invalid
    EXPECT_FALSE(endpoint->open(std::move(options)));
    EXPECT_TRUE(listener->waitForErrors(1U));
    EXPECT_EQ(Websocket::State::Disconnected, endpoint->state());
}

TEST_F(ZaphoydTppFactoryTest, TwoIndependentEndpointsDoNotCrossTalk)
{
    const auto listener1 = std::make_shared<Tests::RecordingListener>();
    const auto listener2 = std::make_shared<Tests::RecordingListener>();
    const auto endpoint1 = openEndpoint(listener1);
    const auto endpoint2 = openEndpoint(listener2);

    ASSERT_TRUE(endpoint1->sendText("from-endpoint-1"));
    ASSERT_TRUE(endpoint2->sendText("from-endpoint-2"));

    ASSERT_TRUE(listener1->waitForTextMessages(1U));
    ASSERT_TRUE(listener2->waitForTextMessages(1U));

    const auto messages1 = listener1->textMessages();
    const auto messages2 = listener2->textMessages();
    ASSERT_EQ(1U, messages1.size());
    ASSERT_EQ(1U, messages2.size());
    EXPECT_EQ("from-endpoint-1", messages1.front());
    EXPECT_EQ("from-endpoint-2", messages2.front());
}
