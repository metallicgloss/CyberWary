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

/*-----------------------------------------------------------------------*\

                        GLOBAL REPORT FUNCTIONALITY

\*-----------------------------------------------------------------------*/

$(document).ready(function() {

    $('.accordion-body button').click(function() {
        // On button click within the accordion body (Next or Previous buttons)

        if ($(this).is('.next')) {
            // Next button clicked.
            $(this).closest( // Find the closest accordion-item (parent)
                '.accordion-item'
            ).nextAll( // Skip to the next of the same type.
                '.accordion-item:first'
            ).find( // Find the collapse element
                '.accordion-collapse'
            ).collapse( // Collapse the element.
                'show'
            )

        } else {
            // Previous button clicked - same as above, but in reverse.
            $(this).closest('.accordion-item').prevAll('.accordion-item:first').find('.accordion-collapse').collapse('show')
        }
    });

    // Determine the max dimensions of the graph.
    calculatedMax = $('#faqAccordion').parent().width() / 2 - 25
    if (calculatedMax < 700) {
        // If less than 700px width, base values on calculations
        maxChartHeight = Math.round(calculatedMax * 0.7)
        maxChartWidth = calculatedMax
    } else {
        // If larger, set max size.
        maxChartHeight = 400
        maxChartWidth = 700
    }

    // Initialise datatables for the five tables.
    $('#credentials, #system-users, #windows-av-exclusions, #installed-patches, #pending-patches').dataTable({
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


function initMap() {
    // Device location map initialisation

    // Reference - https://ref.cyberwary.com/fhil5
    const map = new google.maps.Map(document.getElementById("map"), {
        zoom: 9,
        center: {
            lat: latitude,
            lng: longitude
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
        // Reference - https://ref.cyberwary.com/6mmle
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

    // Create a new map marker for the geolocation for the device.
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


/*-----------------------------------------------------------------------*\

                        INSTALLED APPLICATIONS COMPONENT

\*-----------------------------------------------------------------------*/

if (typeof cve !== 'undefined') {
    // If applications are enabled.

    $(document).ready(function() {
        // Define the max dimensions for the two charts in the component.
        $('#vulnerabilities').css('width', maxChartWidth).css('height', maxChartHeight)
        $('#install-by-time').css('width', maxChartWidth).css('height', maxChartHeight)

        // Create custom datatable with column sizes.
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
            // Reference - https://ref.cyberwary.com/8sca4
            columnDefs: [
                { targets: 0, width: "40%" },
                { targets: 1, width: "20%" },
                { targets: 2, width: "10%", sortable: false },
                { targets: 3, width: "10%", sortable: false },
                { targets: 4, width: "20%" },
            ]
        });

        // Initialise the vulnerable applications doughnut chart.
        // Reference - https://ref.cyberwary.com/edful
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

        // Initialise dataset for race line chart.
        // Reference - https://ref.cyberwary.com/od16p
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

        // Initialise line chart using the series list previously created.
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
                text: 'Applications Installed by Date',
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
        // Collect list of CVE's applicable to a program.

        $.ajax({
            type: "POST",
            url: cveURL,
            dataType: "json",
            data: {
                csrfmiddlewaretoken: csrfToken,
                cpe
            },
            success: function(data) {
                // Reset the table in the modal.
                $('#cve-modal-table').DataTable().clear();
                $('#cve-modal-table').DataTable().destroy();
                $('#cve-modal-table tbody').empty();

                $.each(data, function(index, element) {
                    // For each CVE returned, add a row.
                    // Reference - https://ref.cyberwary.com/74ujn
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
                        // For each reference associated with the CVE, append a reference to the table.
                        $('#cve-modal-table tr:last td:last').append($('<a>')
                            .text(reference['source'] + " (" + reference['tags'] + ")")
                            .attr('href', reference['url'])
                            .attr('target', "_blank")
                        ).append('<br>')
                    });
                });

                // Re-initialise the table containing new data.
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

                // Show the modal.
                $('#cveModal').modal('show');
            }
        });
    }
}


/*-----------------------------------------------------------------------*\

                        BROWSER PASSWORDS COMPONENT

\*-----------------------------------------------------------------------*/

if (typeof credentials !== 'undefined') {
    // Credentials component is enabled.

    $(document).ready(function() {
        // Set the dimensions of the two charts in the component.
        $('#usernames').css('width', maxChartWidth).css('height', maxChartHeight)
        $('#compromised').css('width', maxChartWidth).css('height', maxChartHeight)

        // Initialise pie chart.
        // Reference - https://ref.cyberwary.com/qen31
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

        // Initialise doughnut chart.
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
                radius: ['55%', '65%'], // Converts the Pie chart to the Doughnut
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
        // Collect credential details before displaying in the modal.

        $.ajax({
            type: "POST",
            url: credentialURL,
            dataType: "json",
            data: {
                csrfmiddlewaretoken: csrfToken,
                credentialID
            },
            success: function(data) {
                // Populate modal fields.
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

                // Show modal.
                $('#credentialModal').modal('show');
            }
        });
    }
}


/*-----------------------------------------------------------------------*\

                            FIREWALL COMPONENT

\*-----------------------------------------------------------------------*/

if (typeof firewall !== 'undefined') {
    // If Firewall has been enabled.

    $(document).ready(function() {
        // Create custom datatable with column sizes.
        $('#firewall-rules').dataTable({
            "lengthChange": false,
            "searching": false,
            "pageLength": 10,
            "ordering": true,
            responsive: {
                details: {
                    type: 'column',
                    target: 'tr'
                }
            },
            "autoWidth": false,
            // Reference - https://ref.cyberwary.com/8sca4
            columnDefs: [
                { targets: 0, width: "40%" },
                { targets: 1, width: "20%" },
                { targets: 2, width: "10%" },
                { targets: 2, width: "20%" },
                { targets: 2, width: "10%" },
            ]
        });
    })
}


/*-----------------------------------------------------------------------*\

                            ANTIVIRUS COMPONENT

\*-----------------------------------------------------------------------*/

if (typeof install_antivirus !== 'undefined') {
    // If antivirus enabled.

    $(document).ready(function() {
        // Create custom datatable with column sizes.
        $('#windows-av-detections').dataTable({
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
                { targets: 0, width: "40%" },
                { targets: 1, width: "30%" },
                { targets: 2, width: "30%" }
            ]
        });
    })

    // Append resources to modal before showing.
    function viewResources(resources) {
        $('#resources').text(resources)
        $('#defenderResourceModal').modal('show');
    }
}