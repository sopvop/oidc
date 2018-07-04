#!/usr/bin/env bash
sassc -I vendor/foundation-sites/scss/ css/site.scss \
  | postcss --no-map --use autoprefixer \
  | sassc > static/site.min.css

