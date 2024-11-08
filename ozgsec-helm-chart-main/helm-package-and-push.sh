#!/bin/bash
output=$(helm package ./charts/ozgsec)
package_name=$(cut -d ":" -f2- <<< "$output")
helm cm-push ${package_name} ${CI_PROJECT_NAME}