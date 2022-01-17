/*
Copyright (C) <2021-2022>  <Marius Genheimer>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.
You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>
*/

package main

import "time"

// Structures to accept decrypted BlackMatter Command&Control messages

type Meta struct {
	TimeStamp     time.Time `json:"timestamp"`
	URI           string    `json:"uri"`
	Host          string    `json:"host"`
	Remote        string    `json:"remote"`
	UserAgent     string    `json:"userAgent"`
	ContentLength int       `json:"contentLength"`
	ContentType   string    `json:"contentType"`
}

type DiskInfo struct {
	DiskType string `json:"disk_type"`
	DiskSize string `json:"disk_size"`
	FreeSize string `json:"free_size"`
}

type InfoMsg struct {
	Version      string     `json:"bot_version"`
	ID           string     `json:"bot_id"`
	Company      string     `json:"bot_company"`
	Hostname     string     `json:"host_hostname"`
	OS           string     `json:"host_os"`
	User         string     `json:"host_user"`
	Architecture string     `json:"host_arch"`
	Disk         []DiskInfo `json:"disks_info"`
}

type StatisticsMsg struct {
	Version       string `json:"bot_version"`
	ID            string `json:"bot_id"`
	Company       string `json:"bot_company"`
	FileCount     string `json:"stat_all_files"`
	NotEncrypted  string `json:"stat_not_encrypted"`
	Size          string `json:"stat_size"`
	ExecutionTime string `json:"execution_time"`
	StartTime     string `json:"start_time"`
	StopTime      string `json:"stop_time"`
}

type C2Stats struct {
	MetaData Meta          `json:"meta"`
	Stats    StatisticsMsg `json:"stats"`
}

type C2Info struct {
	MetaData Meta    `json:"meta"`
	Info     InfoMsg `json:"info"`
}
