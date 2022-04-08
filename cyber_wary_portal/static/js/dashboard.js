/*-----------------------------------------------------------------------*\

    GNU General Public License v3.0
    Cyber Wary - <https://github.com/metallicgloss/CyberWary>
    Copyright (C) 2022 - William P - <hello@metallicgloss.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program. If not, see <https://www.gnu.org/licenses/>.

\*-----------------------------------------------------------------------*/

function initMap() {
    const map = new google.maps.Map(document.getElementById("map"), {
        zoom: 6,
        center: {
            lat: 55,
            lng: -3
        },
        minZoom: 2,
        maxZoom: 10,
        restriction: {
            latLngBounds: {
                north: 85,
                south: -85,
                west: -180,
                east: 180
            }
        },
        disableDefaultUI: true,
        gestureHandling: "cooperative",
        zoomControl: true,
        styles: [{
                "elementType": "geometry",
                "stylers": [{
                    "color": "#1d1c28"
                }]
            },
            {
                "elementType": "labels.icon",
                "stylers": [{
                    "visibility": "off"
                }]
            },
            {
                "elementType": "labels.text.stroke",
                "stylers": [{
                        "color": "#1d1c28"
                    },
                    {
                        "visibility": "on"
                    },
                    {
                        "weight": 2.5
                    }
                ]
            },
            {
                "featureType": "administrative",
                "elementType": "labels.text.fill",
                "stylers": [{
                    "color": "#e9e9e9"
                }]
            },
            {
                "featureType": "landscape.natural",
                "elementType": "labels",
                "stylers": [{
                    "visibility": "off"
                }]
            },
            {
                "featureType": "poi",
                "stylers": [{
                    "visibility": "off"
                }]
            },
            {
                "featureType": "road",
                "elementType": "geometry",
                "stylers": [{
                    "color": "#2e2d40"
                }]
            },
            {
                "featureType": "road",
                "elementType": "labels",
                "stylers": [{
                    "visibility": "off"
                }]
            },
            {
                "featureType": "road",
                "elementType": "labels.icon",
                "stylers": [{
                    "visibility": "off"
                }]
            },
            {
                "featureType": "transit",
                "stylers": [{
                    "visibility": "off"
                }]
            },
            {
                "featureType": "water",
                "elementType": "geometry",
                "stylers": [{
                    "color": "#ffffff"
                }]
            },
            {
                "featureType": "water",
                "elementType": "labels.text.fill",
                "stylers": [{
                    "color": "#ffffff"
                }]
            }
        ]
    });

    for (var i = 0; i < markers.length; i++) {
        new google.maps.Marker({
            position: {
                lat: markers[i][0],
                lng: markers[i][1]
            },
            map,
            icon: icon,
            title: title,
        });
    }
}


$(document).ready(function() {

    calculatedMax = $('.chart-block').parent().width() / 2 - 25
    if (calculatedMax < 500) {
        maxChartHeight = Math.round(calculatedMax * 0.7)
        maxChartWidth = calculatedMax
    } else {
        maxChartHeight = 300
        maxChartWidth = 500
    }

    $('#applications, #credentials, #scans').dataTable({
        "lengthChange": false,
        "searching": false,
        "pageLength": 8,
        "ordering": false,
        responsive: {
            details: {
                type: 'column',
                target: 'tr'
            }
        },
    });


    $('#operating-systems').css('width', maxChartWidth).css('height', maxChartHeight)

    echarts.init(document.getElementById('operating-systems')).setOption({
        title: {
            display: true,
            text: 'Operating Systems Scanned',
            textStyle: {
                color: '#272727',
                fontWeight: 'normal',
                fontFamily: 'Space Mono',
                fontSize: 16
            },
            left: '48%',
            textAlign: 'center'
        },
        tooltip: {
            trigger: 'item'
        },
        series: [{
            name: 'Operating Systems Scanned',
            type: 'pie',
            radius: ['55%', '65%'],
            center: ['50%', '50%'],
            avoidLabelOverlap: false,
            itemStyle: {
                shadowBlur: 30,
                shadowColor: 'rgba(0, 0, 0, 0.3)'
            },
            data: operatingSystems
        }]
    });

})