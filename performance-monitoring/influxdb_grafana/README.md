# InfluxDB / Grafana

InfluxDB is a time series database designed to ingest metric and measurement data, and grafana is a visualization tool designed to read from many data sources including influxdb to present this data in the form of web based dashboards.  This project will walk through standing up and configuring an InfluxDB database and an instance of grafana using docker-compose.

## Prerequisites

- Install [Docker Compose](https://github.com/docker/compose) on the system.

## Container Setup

To deploy a container based on this image, follow the steps below:

1. Clone this repo into a folder on your docker host. 
```
git clone 
``` 
1. On the Docker host, create the **docker-compose.yml** file. A sample **docker-compose.yml** file is included in this repository.
1. Change into the **mx-tools/performance-monitoring/influxdb_grafana/docker-compose.yml** folder.
   - `host# cd mx-tools/performance-monitoring/influxdb_grafana`
1. Use **docker-compose** to bring up the container:
   - `host# docker-compose up -d`

1. Verify the containers are running correctly with the `docker ps` command.
```
$ docker ps
CONTAINER ID        IMAGE                    COMMAND                  CREATED             STATUS                  PORTS                    NAMES
8ba091352752        grafana/grafana:latest   "/run.sh"                36 minutes ago      Up 35 minutes           0.0.0.0:3000->3000/tcp   grafana
f9d92248d41f        influxdb:latest          "/entrypoint.sh infl…"   36 minutes ago      Up 35 minutes           0.0.0.0:8086->8086/tcp   influxdb
```

## Configure InfluxDB database
1. Access a bash session via terminal window into the influxdb container using the following `docker exec` command, and create the database.
```
$ docker exec -it influxdb /bin/bash -l
influx
CREATE DATABASE imperva_performance_stats
SHOW DATABASES
exit
```

## Configure Grafana and import the dashboards
Create influxdb datasource in grafana, and import performance monitoring dashboards.

#### Create InfluxDB Datasource ####

1. Navigate to grafana via a browser referencing the IP of your docker host.  In this example, it is run locally on a work station and access with the following: [http://localhost:3000](http://localhost:3000)

1. Log in with admin/admin, and create a new password.

1. Click `Add datasource`, and add a new InfluxDB datasource with the following:

   `Name` - _(required)_ the name of the data source: `Imperva Performance Stats`

   `URL` - _(required)_ the endpoint of influxdb: `http://localhost:8086`.

   `Database` - _(required)_ name of database `imperva_performance_stats`.

   `HTTP Method` - _(required)_ the HTTP method used to push data into influxdb `POST`

1. Click `Save & Test` to validate grafana is able to access the datasource correctly.

#### Import Grafana Dashboards ####
1. Navigate to Home screen by clicking the Grafana logo in the top left corner.

1. Import each of dashboard files in the `mx-tools/performance-monitoring/influxdb_grafana/grafana_dashboards` directory by repeating the following steps:
  -  Click `+ -> Create -> Import` to import a dashboard

1. Click `Upload JSON file` and one dashboard at a time to import repeating this process for each.


