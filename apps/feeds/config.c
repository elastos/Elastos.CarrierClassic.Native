/*
 * Copyright (c) 2020 Elastos Foundation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <string.h>

#include <crystal.h>
#include <libconfig.h>

#include "carrier_config.h"
#include "config.h"

static
int extra_config_parser(void *p, ElaOptions *options)
{
    FeedsConfig *fc = (FeedsConfig *)options;
    config_t *cfg = (config_t *)p;
    config_setting_t *publishers_setting;
    int entries;
    int i;

    publishers_setting = config_lookup(cfg, "publishers");
    if (!publishers_setting) {
        fprintf(stderr, "Missing publishers section.\n");
        return -1;
    }

    entries = config_setting_length(publishers_setting);
    if (entries <= 0) {
        fprintf(stderr, "Empty publishers option.\n");
        return -1;
    }

    fc->publishers_cnt = entries;

    fc->publishers = rc_zalloc(sizeof(fc->publishers[0]) * fc->publishers_cnt, NULL);
    if (!fc->publishers)
        return -1;

    for (i = 0; i < entries; ++i) {
        const char *publisher_node_id;

        publisher_node_id = config_setting_get_string_elem(publishers_setting, i);
        if (!publisher_node_id || !publisher_node_id[0] ||
            !ela_id_is_valid(publisher_node_id)) {
            fprintf(stderr, "Invalid publisher option.\n");
            deref(fc->publishers);
            fc->publishers = NULL;
            return -1;
        }

        strcpy(fc->publishers[i], publisher_node_id);
    }

    return 0;
}

FeedsConfig *load_config(const char *config_file, FeedsConfig *config)
{
    memset(config, 0, sizeof(FeedsConfig));

    return (FeedsConfig *)carrier_config_load(config_file, extra_config_parser,
                                              (ElaOptions *)config);
}

void free_config(FeedsConfig *config)
{
    if (!config)
        return;

    carrier_config_free(&(config->ela_options));
    deref(config->publishers);

    memset(config, 0, sizeof(FeedsConfig));
}
