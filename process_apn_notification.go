package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/sideshow/apns2"
	log "github.com/sirupsen/logrus"
)

type Message struct {
	isProduction   bool
	notification   *apns2.Notification
	unsubscribeUrl string
	requestLog     *log.Entry // For logging with datadog context
	ctx            context.Context
}

func apnNotificationsWorker(workerId int, httpClient *http.Client) {
	log.Info(fmt.Sprintf("starting worker %d", workerId))
	defer log.Info(fmt.Sprintf("stopping worker %d", workerId))

	for msg := range messageChan {
		processApnNotificationMessage(msg, httpClient, workerId)
	}
}

func processApnNotificationMessage(msg *Message, httpClient *http.Client, workerId int) {
	span, sctx := tracer.StartSpanFromContext(msg.ctx,
		"processMessage",
		tracer.Tag("workerId", workerId),
		tracer.Tag("deviceToken", msg.notification.DeviceToken),
	)
	defer span.Finish()

	var client *apns2.Client
	if msg.isProduction {
		client = productionClient
	} else {
		client = developmentClient
	}

	res, err := client.Push(msg.notification)

	if err != nil {
		msg.requestLog.Error(fmt.Sprintf("Push error: %s", err))
		return
	}

	if !res.Sent() {
		unsubscribed := false

		// 410 status means that the token is invalid. This is a definitive error, and we should remove the subscription
		// from the originating server to avoid continuing sending requests that will never work again.
		// See https://developer.apple.com/documentation/usernotifications/handling-notification-responses-from-apns
		if msg.unsubscribeUrl != "" && res.StatusCode == 410 {
			unsubscribed = unsubscribe(msg.unsubscribeUrl, httpClient, sctx, msg.requestLog)
		}

		msg.requestLog.WithFields(log.Fields{
			"status-code":  res.StatusCode,
			"apns-id":      res.ApnsID,
			"reason":       res.Reason,
			"unsubscribed": unsubscribed,
		}).Error(fmt.Sprintf("Failed to send notification (%v)", res.StatusCode))

		return
	}

	msg.requestLog.WithFields(log.Fields{
		"status-code":  res.StatusCode,
		"apns-id":      res.ApnsID,
		"reason":       res.Reason,
		"device-token": msg.notification.DeviceToken,
		"expiration":   msg.notification.Expiration,
		"priority":     msg.notification.Priority,
		"collapse-id":  msg.notification.CollapseID,
	}).Info(fmt.Sprintf("Sent notification (%v)", res.StatusCode))
}

func unsubscribe(unsubscribeUrl string, httpClient *http.Client, ctx context.Context, requestLog *log.Entry) bool {
	span, sctx := tracer.StartSpanFromContext(ctx, "unsubscribe",
		tracer.Tag("unsubscribeUrl", unsubscribeUrl),
	)
	defer span.Finish()

	unsubscribeReq, reqErr := http.NewRequestWithContext(sctx, "DELETE", unsubscribeUrl, nil)
	if reqErr != nil {
		requestLog.WithFields(log.Fields{
			"error":           reqErr.Error(),
			"unsubscribe-url": unsubscribeUrl,
		}).Error("Failed to create HTTP request for unsubscribe")
		return false
	}

	defer unsubscribeReq.Body.Close()

	unsubscribeResp, respErr := httpClient.Do(unsubscribeReq)
	if respErr != nil {
		requestLog.WithFields(log.Fields{
			"error":           respErr.Error(),
			"unsubscribe-url": unsubscribeUrl,
		}).Error("Failed to send unsubscribe request")
		return false
	}

	if unsubscribeResp.StatusCode == 200 {
		return true
	} else {
		requestLog.WithFields(log.Fields{
			"status-code":     unsubscribeResp.StatusCode,
			"unsubscribe-url": unsubscribeUrl,
		}).Error(fmt.Sprintf("Failed to unsubscribe for notification (%v)", unsubscribeResp.StatusCode))
		return false
	}
}
