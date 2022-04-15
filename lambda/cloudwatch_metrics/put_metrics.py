"""Handler for parsing Node Exporter json to AWS Cloudwatch Metrics

Node Exporter and Cloudwatch use two very different schemas for their data
This lambda takes the messy Node out and formats and submits it to Cloudwatch
metrics for us to track device health over time.
"""
import boto3
import time
import logging
import videon_shared as videon

cloudwatch = boto3.client("cloudwatch")
logger = logging.getLogger()


# Videon lambda function for processing node_exporter json and
# submitting metrics to cloudwatch
def lambda_handler(event, context):  # pylint: disable=unused-argument

    # Function to append the current metric to the current list, and send it up
    # to cloudwatch if a new namespace is found, or if we are at the
    # put_metric_data limit of 20 metrics per call.
    def append_and_send(cur_metric, metric_list, metric_count,
                        current_namespace, previous_namespace, responses_count):
        if metric_count == 20 or (current_namespace != previous_namespace and
                                  previous_namespace is not None):
            if current_namespace != previous_namespace:
                uploaded_namespace = previous_namespace
            else:
                uploaded_namespace = current_namespace

            response = cloudwatch.put_metric_data(Namespace=uploaded_namespace,
                                                  MetricData=metric_list)
            responses_count += 1

            logger.info("Response from put to %s: %s", uploaded_namespace,
                        response)

            # Reset Values for next send
            metric_count = 0
            metric_list.clear()
        # Add current metric dictionary to list of metrics
        metric_list.append(cur_metric)
        metric_count += 1
        return metric_count, responses_count

    videon.setup_logging(logging.INFO, event)

    # Names of custom videon domains to be used for grouping our metrics
    # These allow us to group metrics for easier aggregation as well as reducing
    # the number of calls to put_metric_data
    namespace_cpu = "Videon/Custom/cpu"
    namespace_thermal = "Videon/Custom/thermal"
    namespace_network = "Videon/Custom/network"
    namespace_memory = "Videon/Custom/memory"
    namespace_filesystem = "Videon/Custom/filesystem"
    namespace_uncategorized = "Videon/Custom/Uncategorized"

    # Set timestamp to when the data was received and processed for all metrics
    timestamp = time.time()

    # Top level unsorted list of all metrics to be filled with dictionaries
    # for each metric
    metrics = []

    for key, value in event.items():
        if key == "device_guid":
            continue
        # Determine namespace, will be used to sort/split metrics
        if "cpu" in key:
            namespace = namespace_cpu
        elif "thermal" in key:
            namespace = namespace_thermal
        elif "memory" in key:
            namespace = namespace_memory
        elif "filesystem" in key:
            namespace = namespace_filesystem
        elif r"network" in key:
            namespace = namespace_network
        else:
            namespace = namespace_uncategorized

        # Template for a metric dictionary to be used as part of the call to
        # put_metric_data. This structure doesn't need fully defined here,
        # but it makes it much easier to see what happening
        metric = {
            "MetricName": key,
            "Timestamp": timestamp,
            "Dimensions": [{
                "Name": "device_guid",
                "Value": event["device_guid"]
            }],
            "Value": value,
            "StorageResolution": 1,
            "Namespace": namespace
        }

        if "bytes" in key:
            metric["Unit"] = "Bytes"
        elif "percent" in key:
            metric["Unit"] = "Percent"
        elif "_temp_" in key:
            metric["Unit"] = "Count"
        elif "seconds" in key:
            metric["Unit"] = "Seconds"
        metrics.append(metric)

    # We need to sort the metrics by namespace since only one namespace is
    # allowed for each call to put_metric_data. We also need to be able to send
    # as many metrics as possible together to reduce calls
    sorted_metrics = sorted(metrics, key=lambda d: d["Namespace"])

    # Reset metrics to an empty list now that we have the sorted list.
    # We will use this container to store up to 20 metrics at one time for
    # most efficient calls to the 'put_metric_data' endpoint
    metrics = []
    metrics_count = 0
    response_count = 0
    prev_namespace = None

    for m in sorted_metrics:
        m_namespace = m["Namespace"]
        # The namespace can"t live in the metric dictionary when submitted,
        # so now that we have it and are ready for submission,
        # delete it to maintain proper dictionary format
        del m["Namespace"]
        if m_namespace == namespace_cpu:
            metrics_count, response_count = append_and_send(
                m, metrics, metrics_count, m_namespace, prev_namespace,
                response_count)
            prev_namespace = namespace_cpu
        elif m_namespace == namespace_thermal:
            metrics_count, response_count = append_and_send(
                m, metrics, metrics_count, m_namespace, prev_namespace,
                response_count)
            prev_namespace = namespace_thermal
        elif m_namespace == namespace_network:
            metrics_count, response_count = append_and_send(
                m, metrics, metrics_count, m_namespace, prev_namespace,
                response_count)
            prev_namespace = namespace_network
        elif m_namespace == namespace_memory:
            metrics_count, response_count = append_and_send(
                m, metrics, metrics_count, m_namespace, prev_namespace,
                response_count)
            prev_namespace = namespace_memory
        elif m_namespace == namespace_filesystem:
            metrics_count, response_count = append_and_send(
                m, metrics, metrics_count, m_namespace, prev_namespace,
                response_count)
            prev_namespace = namespace_filesystem
        elif m_namespace == namespace_uncategorized:
            metrics_count, response_count = append_and_send(
                m, metrics, metrics_count, m_namespace, prev_namespace,
                response_count)
            prev_namespace = namespace_uncategorized

    put_response = cloudwatch.put_metric_data(Namespace=prev_namespace,
                                              MetricData=metrics)
    response_count += 1
    logger.info("Response from put to %s: %s", prev_namespace, put_response)

    logger.info("Made a total of %s calls to 'put_metric_data'", response_count)

    return videon.response_json(
        200, {"message": "Metric Data submitted successfully."}, event)
