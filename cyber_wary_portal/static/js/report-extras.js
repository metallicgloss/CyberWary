/*-----------------------------------------------------------------------*\

    GNU General Public License v3.0
    Cyber Wary - <https://github.com/metallicgloss/CyberWary>
    Copyright (C) 2021 - William P - <hello@metallicgloss.com>

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

$(document).ready(function() {
    $('.accordion-body button').click(function() {
        if ($(this).is('.next')) {
            $(this).closest('.accordion-item').next().find('.accordion-collapse').collapse('show')
        } else {
            $(this).closest('.accordion-item').prev().find('.accordion-collapse').collapse('show')
        }
    });

    maxChartDimensions = $('#faqAccordion').parent().width() / 2 - 25

    $('#credentials, #system-users').dataTable({
        "lengthChange": false,
        "searching": false,
        "pageLength": 10,
        "ordering": false,
        responsive: {
            details: {
                type: 'column',
                target: 'tr'
            }
        },
    });
});


if (typeof cve !== 'undefined') {
    $(document).ready(function() {
        $('#vulnerabilities').css('width', maxChartDimensions).css('height', maxChartDimensions - 50)
        $('#install-by-time').css('width', maxChartDimensions).css('height', maxChartDimensions - 50)

        $('#applications').dataTable({
            "lengthChange": false,
            "searching": false,
            "pageLength": 10,
            "ordering": true,
            "order": [
                [4, "asc"],
                [0, "asc"]
            ],
            responsive: {
                details: {
                    type: 'column',
                    target: 'tr'
                }
            },
            "autoWidth": false,
            columnDefs: [
                { targets: 0, width: "40%" },
                { targets: 1, width: "20%" },
                { targets: 2, width: "10%", sortable: false },
                { targets: 3, width: "10%", sortable: false },
                { targets: 4, width: "20%" },
            ]
        });

        echarts.init(document.getElementById('vulnerabilities')).setOption({
            title: {
                display: true,
                text: 'Vulnerable Applications',
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
                name: 'Applications',
                type: 'pie',
                radius: ['55%', '65%'],
                center: ['50%', '50%'],
                avoidLabelOverlap: false,
                itemStyle: {
                    shadowBlur: 30,
                    shadowColor: 'rgba(0, 0, 0, 0.3)'
                },
                data: [{
                        value: vulnerableApplications,
                        name: 'Detected as Vulnerable',
                        itemStyle: {
                            color: '#D06262'
                        }
                    },
                    {
                        value: totalApplications - vulnerableApplications,
                        name: 'No Vulnerabilities Detected',
                        itemStyle: {
                            color: '#4adfab'
                        }
                    },
                ]
            }]
        });

        const datasetWithFilters = [];
        const seriesList = [];

        datasetWithFilters.push({
            id: 'installed_applications',
            fromDatasetId: 'applications',
            transform: {
                type: 'filter',
                config: {
                    and: [{
                        dimension: 'Installed',
                        '=': "Installed Applications"
                    }]
                }
            }
        });

        seriesList.push({
            type: 'line',
            datasetId: 'installed_applications',
            showSymbol: false,
            color: "#34CC96",
            name: "Installed Applications",
            labelLayout: {
                moveOverlap: 'shiftY'
            },
            emphasis: {
                focus: 'series'
            },
            encode: {
                x: 'Day',
                y: 'Installed Applications'
            }
        });

        echarts.init(document.getElementById("install-by-time")).setOption({
            animationDuration: 10000,
            dataset: [{
                    id: 'applications',
                    source: installTimeline
                },
                ...datasetWithFilters
            ],
            title: {
                display: true,
                text: 'Applications Installed',
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
                order: 'valueDesc',
                trigger: 'axis'
            },
            xAxis: {
                type: 'category',
                nameLocation: 'middle'
            },
            yAxis: {
                name: false
            },
            series: seriesList,
            responsive: true,
            maintainAspectRatio: false
        });
    });

    function viewCVE(cpe) {
        $.ajax({
            type: "POST",
            url: cveURL,
            dataType: "json",
            data: {
                csrfmiddlewaretoken: csrfToken,
                cpe
            },
            success: function(data) {
                $('#cve-modal-table').DataTable().clear();
                $('#cve-modal-table').DataTable().destroy();

                $('#cve-modal-table tbody').empty();

                $.each(data, function(index, element) {
                    $('#cve-modal-table').find('tbody')
                        .append($('<tr>')
                            .append($('<td>')
                                .append(index)
                            )
                            .append($('<td>')
                                .append(element['severity_rating'])
                            )
                            .append($('<td>')
                                .append(element['severity_score'])
                            )
                            .append($('<td>')
                                .append(element['published'])
                            )
                            .append($('<td>'))
                        );

                    $.each(element['references'], function(index, reference) {
                        $('#cve-modal-table tr:last td:last').append($('<a>')
                            .text(reference['source'] + " (" + reference['tags'] + ")")
                            .attr('href', reference['url'])
                            .attr('target', "_blank")
                        ).append('<br>')
                    });

                });

                $('#cve-modal-table').DataTable({
                    "lengthChange": false,
                    "searching": false,
                    "pageLength": 10,
                    "ordering": false,
                    responsive: {
                        details: {
                            type: 'column',
                            target: 'tr'
                        }
                    },
                    "autoWidth": false,
                    columnDefs: [
                        { targets: 0, width: "20%" },
                        { targets: 1, width: "15%" },
                        { targets: 2, width: "15%" },
                        { targets: 3, width: "15%" },
                        { targets: 4, width: "35%" },
                    ]
                });
                $('#cveModal').modal('show');
            }
        });
    }
}

if (typeof credentials !== 'undefined') {
    $(document).ready(function() {
        $('#usernames').css('width', maxChartDimensions).css('height', maxChartDimensions - 50)
        $('#compromised').css('width', maxChartDimensions).css('height', maxChartDimensions - 50)

        echarts.init(document.getElementById('usernames')).setOption({
            title: {
                display: true,
                text: 'Usernames & Email Addresses',
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
                trigger: 'item',
                formatter: '{a}<br/>{b}: {d}%'
            },
            visualMap: {
                show: false,
                min: 5,
                max: 100,
                inRange: {
                    color: '#34cc96',
                    colorLightness: [0.2, 1]
                }
            },
            series: [{
                name: 'Usernames',
                type: 'pie',
                radius: '65%',
                center: ['50%', '50%'],
                roseType: 'radius',
                data: usernameData.sort(function(a, b) { return a.value - b.value; }),
                itemStyle: {
                    shadowBlur: 30,
                    shadowColor: 'rgba(0, 0, 0, 0.3)'
                },
                animationType: 'scale',
                animationEasing: 'elasticOut',
                animationDelay: function(idx) {
                    return Math.random() * 200;
                }
            }]
        });

        echarts.init(document.getElementById('compromised')).setOption({
            title: {
                display: true,
                text: 'Compromised Passwords',
                textStyle: {
                    color: compromisedColor,
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
                name: 'Password',
                type: 'pie',
                radius: ['55%', '65%'],
                center: ['50%', '50%'],
                avoidLabelOverlap: false,
                itemStyle: {
                    shadowBlur: 30,
                    shadowColor: 'rgba(0, 0, 0, 0.3)'
                },
                data: [{
                        value: compromisedValue,
                        name: 'Potentially Compromised',
                        itemStyle: {
                            color: '#D06262'
                        }
                    },
                    {
                        value: undetectedValue,
                        name: 'Not Detected in Dataset',
                        itemStyle: {
                            color: '#4adfab'
                        }
                    },
                ]
            }]
        });
    });

    function viewCredential(credentialID) {
        $.ajax({
            type: "POST",
            url: credentialURL,
            dataType: "json",
            data: {
                csrfmiddlewaretoken: csrfToken,
                credentialID
            },
            success: function(data) {
                $('#credUsername').text(data.username);
                $('#credStrength').text(data.password_strength);
                $('#credURL').text(data.url);
                $('#credBrowser').text(data.browser);
                $('#credFilename').text(data.filename);

                if (data.compromised) {
                    $('#credCompromised').text("Potentially Compromised");
                } else {
                    $('#credCompromised').text("Not Detected");
                }
                $('#credOccurrence').text(data.occurrence);
                $('#credentialModal').modal('show');
            }
        });
    }
}

function initMap() {
    const map = new google.maps.Map(document.getElementById("map"), {
        zoom: 9,
        center: {
            lat: latitude,
            lng: longitude
        },
        disableDefaultUI: true,
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
                    "visibility": "off"
                }]
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
                    "color": "#3a3850"
                }]
            },
            {
                "featureType": "water",
                "elementType": "labels.text.fill",
                "stylers": [{
                    "color": "#ffffff"
                }]
            }
        ],
    });

    new google.maps.Marker({
        position: {
            lat: latitude,
            lng: longitude
        },
        map,
        icon: icon,
        title: title,
    });
}