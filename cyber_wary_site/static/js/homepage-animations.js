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

var played = false;

if (!/Android|webOS|iPhone|iPad|iPod|BlackBerry/i.test(navigator.userAgent)) {
    // If on a portable device (targetting mobile devices).

    function elementInView(element) {
        // Function to check if the element is in the browser view.
        return (
            (
                $(element).offset().top <= $(window).scrollTop() + $(window).height()
            ) &&
            (
                $(element).offset().top >= $(window).scrollTop()
            )
        );
    }


    $(window).scroll(function() {
        // When page scrolls, check if the trigger feature element is in view.
        if (elementInView('#trigger-feature') && !played) {
            // If in view, and animation hasn't played before, execute play for animejs animation.
            notifications.play()
            played = true;
        }
    });

    // Define new animejs animation - timeline (bouncing in notifications)
    var notifications = anime.timeline({
        duration: 600,
        autoplay: false,
        easing: 'linear',
        loop: false,
    });

    // Target bottom notification, bounce to the top, and then back into place.
    notifications.add({
        targets: document.querySelectorAll('.notification-box .notification')[3],
        keyframes: [{
                translateY: -258
            },
            {
                opacity: [0, 1]
            },
            {
                translateY: [-258, 0],
                delay: 200
            }
        ],
    })

    // Target 2nd to bottom notification, bounce to the top, and then back into place.
    notifications.add({
        targets: document.querySelectorAll('.notification-box .notification')[2],
        keyframes: [{
                translateY: -172
            }, {
                opacity: [0, 1]
            },
            {
                translateY: [-172, 0],
                delay: 200
            }
        ],
    })

    // Target second notification, bounce to the top, and then back into place.
    notifications.add({
        targets: document.querySelectorAll('.notification-box .notification')[1],
        keyframes: [{
                translateY: -86
            },
            {
                opacity: [0, 1]
            },
            {
                translateY: [-86, 0],
                delay: 200
            }
        ],
    })

    // Target first notification, bounce into view.
    notifications.add({
        targets: document.querySelectorAll('.notification-box .notification')[0],
        keyframes: [{
            opacity: [0, 1]
        }],
        duration: 200 // Define shorter animation as no movement required.
    })
}

$(".scan-button").click(function() {
    // When scan-button animation is executed.

    // Define new animejs animation to move the button SVG around the box.
    anime({
        targets: document.querySelectorAll('.scan-now'),
        keyframes: [{
                translateY: -134
            },
            {
                translateX: 134
            }
        ],
        duration: 600,
        autoplay: true,
        easing: 'cubicBezier(0.895, 0.030, 0.145, 0.995)', // Use Cubic Bezier curve for bounce animation style.
        loop: false
    });

    // Prevent href redirect for 0.7 seconds until animation has completed to appear like a smooth transition.
    var href = $(this).attr('href');
    setTimeout(function() {
        window.location = href
    }, 700);

    return false;
})

$(".learn-more-button").click(function() {
    // When learn-more-button animation is executed.

    // Define new animejs animation to move the button SVG to the bottom of the box.
    anime({
        targets: document.querySelectorAll('#learn-more'),
        translateY: 148,
        duration: 600,
        autoplay: true,
        easing: 'cubicBezier(0.895, 0.030, 0.145, 0.995)',
        loop: false
    });

    // Prevent href redirect for 0.7 seconds until animation has completed to appear like a smooth transition.
    var href = $(this).attr('href');
    setTimeout(function() {
        window.location = href
    }, 700);

    return false;
})


$('.scan-button, .learn-more-button').mouseover(function() {
    // When mouseover, apply filter css to SVG to alter the brightness of the box, and rotate the arrow around.
    $(this).closest('a').find('svg').eq(0).css("filter", "brightness(0.8)")
    $(this).closest('a').find('svg').eq(1).css("transform", "rotate(360deg)");

}).mouseout(function() {
    // When mouseout, undo effect.
    $(this).closest('a').find('svg').eq(0).css("filter", "none")
    $(this).closest('a').find('svg').eq(1).css("transform", "rotate(0deg)");
});