var played = false;

$(window).scroll(function() {
    function elementScrolled(elem) {
        var docViewTop = $(window).scrollTop();
        var elemTop = $(elem).offset().top;
        return ((elemTop <= docViewTop + $(window).height()) && (elemTop >= docViewTop));
    }

    if (elementScrolled('#last-feature') && !played) {
        notifications.play()
        played = true;
    }
});

var notifications = anime.timeline({
    duration: 500,
    autoplay: false,
    easing: 'easeInOutSine',
    loop: false,
});

notifications.add({
    targets: document.querySelectorAll('.notification-pane .notification')[3],
    keyframes: [{
            translateY: -258,
            opacity: [
                0,
                1
            ]
        },
        {
            translateY: [-258,
                0
            ]
        }
    ],
})

notifications.add({
    targets: document.querySelectorAll('.notification-pane .notification')[2],
    keyframes: [{
            translateY: -172,
            opacity: [
                0,
                1
            ]
        },
        {
            translateY: [-172,
                0
            ]
        }
    ],
})

notifications.add({
    targets: document.querySelectorAll('.notification-pane .notification')[1],
    keyframes: [{
            translateY: -86,
            opacity: [
                0,
                1
            ]
        },
        {
            translateY: [-86,
                0
            ]
        }
    ],
})

notifications.add({
    targets: document.querySelectorAll('.notification-pane .notification')[0],
    keyframes: [{
        opacity: [
            0,
            1
        ]
    }],
    duration: 300
})

$(".scan-button").click(function() {
    anime({
        targets: document.querySelectorAll('#scan-now'),
        keyframes: [{
                translateY: -134
            },
            {
                translateX: 134
            }
        ],
        duration: 600,
        autoplay: true,
        easing: 'cubicBezier(0.895, 0.030, 0.145, 0.995)',
        loop: false
    });

    var href = $(this).attr('href');
    setTimeout(function() {
        window.location = href
    }, 700);

    return false;
})

$(".learn-button").click(function() {
    anime({
        targets: document.querySelectorAll('#learn-more'),
        translateY: 148,
        duration: 600,
        autoplay: true,
        easing: 'cubicBezier(0.895, 0.030, 0.145, 0.995)',
        loop: false
    });

    var href = $(this).attr('href');
    setTimeout(function() {
        window.location = href
    }, 700);

    return false;
})

$('.scan-button, .learn-button').mouseover(function() {
    $(this).closest('a').find('svg').eq(0).css("filter", "brightness(0.8)")
    $(this).closest('a').find('svg').eq(1).css("transform", "rotate(360deg)");
}).mouseout(function() {
    $(this).closest('a').find('svg').eq(0).css("filter", "none")
    $(this).closest('a').find('svg').eq(1).css("transform", "rotate(0deg)");
});