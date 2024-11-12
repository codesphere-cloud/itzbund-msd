#!/bin/bash

export RABBITMQ_NODENAME=cs_rabbitmq

export RABBITMQ_DEFAULT_USER=rabbitmq
export RABBITMQ_DEFAULT_PASS=rabbitmq
export RABBITMQ_PID_FILE=/home/user/app/rabbitmq/mnesia.pid
export RABBITMQ_CONFIG_FILE=/home/user/app/rabbitmq/rabbitmq.conf
export RABBITMQ_FEATURE_FLAGS_FILE=/home/user/app/rabbitmq/feature_flags
export RABBITMQ_LOG_BASE=/home/user/app/rabbitmq/logs
export RABBITMQ_MNESIA_BASE=/home/user/app/rabbitmq/mnesia
