<?php

class DigiSamuraiPlugin {
    function head() {
        ?>
        <link rel="stylesheet" href="https://fonts.googleapis.com/icon?family=Material+Icons">
        <script nonce="">
        document.addEventListener("DOMContentLoaded", function() {
            // 1. Password field toggle eye button
            const passField = document.querySelector('input[type="password"]');
            if (passField) {
                const wrapper = document.createElement('div');
                wrapper.className = 'password-wrapper';
                passField.parentNode.insertBefore(wrapper, passField);
                wrapper.appendChild(passField);
                
                const eyeBtn = document.createElement('button');
                eyeBtn.type = 'button';
                eyeBtn.className = 'password-toggle';
                eyeBtn.innerHTML = '👁️';
                eyeBtn.addEventListener('click', function() {
                    if (passField.type === 'password') {
                        passField.type = 'text';
                        eyeBtn.innerHTML = '🔒';
                    } else {
                        passField.type = 'password';
                        eyeBtn.innerHTML = '👁️';
                    }
                });
                wrapper.appendChild(eyeBtn);
            }

            // 2. Reorder sidebar menu elements
            const menu = document.getElementById('menu');
            if (menu) {
                // Create Digi Samurai Brand Header at the top
                const brand = document.createElement('div');
                brand.className = 'brand-header';
                brand.innerHTML = '<div class="brand-title">Digi Samurai</div><div class="brand-subtitle">Database Console</div>';
                menu.insertBefore(brand, menu.firstChild);

                // Move Language selector to the top (right after the brand)
                const lang = document.getElementById('lang') || document.querySelector('form[action=""] select[name="lang"]')?.closest('form');
                if (lang) {
                    brand.parentNode.insertBefore(lang, brand.nextSibling);
                    lang.classList.add('menu-lang');
                }

                // Move original h1 to the bottom
                const originalH1 = menu.querySelector('h1:not(.brand-header)');
                if (originalH1) {
                    menu.appendChild(originalH1);
                    originalH1.classList.add('original-h1');
                }
            }
            // 3. Populate empty select options
            document.querySelectorAll('select option').forEach(opt => {
                if (opt.value === "" && !opt.textContent.trim()) {
                    opt.textContent = "–";
                }
            });
        });
        </script>
        <style>
        .password-wrapper {
            position: relative;
            display: inline-block;
            width: 100%;
        }
        .password-toggle {
            position: absolute;
            right: 12px;
            top: 50%;
            transform: translateY(-50%);
            background: none !important;
            border: none !important;
            padding: 0 !important;
            cursor: pointer;
            font-size: 14px;
            line-height: 1;
            box-shadow: none !important;
            color: #800000 !important;
        }
        .menu-lang {
            display: block !important;
            margin: 10px 0 20px 0 !important;
            position: static !important;
        }
        .menu-lang select {
            width: 100% !important;
        }
        </style>
        <?php
        return false;
    }
}

return new DigiSamuraiPlugin();
