/**
 * Copyright (c) 2024 Araf Karsh Hamid
 * <p>
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * <p>
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 * <p>
 * This program and the accompanying materials are dual-licensed under
 * either the terms of the Eclipse Public License v1.0 as published by
 * the Eclipse Foundation
 * <p>
 * or (per the licensee's choosing)
 * <p>
 * under the terms of the Apache 2 License version 2.0
 * as published by the Apache Software Foundation.
 */
package io.fusion.air.microservice.adapters.logging.examples.metrics;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.stereotype.Component;

/**
 * ms-springboot-334-vanilla / _5_CustomTagsExample 
 *
 * @author: Araf Karsh Hamid
 * @version: 0.1
 * @date: 2024-10-08T14:22
 */
@Component
public class _5_CustomTagsExample {

    // @Autowired not required - Constructor based Autowiring
    private final Counter taggedCounter;

    /**
     * Constructor for Autowiring
     * @param meterRegistry
     */
    public _5_CustomTagsExample(MeterRegistry meterRegistry) {
        this.taggedCounter = Counter.builder("fusion.air.example.5.customTags")
                // Tags are Key Value Pairs - Gives different dimensions for the metric
                .tags("endpoint", "/api/resource")
                .tags("status", "secured")
                .register(meterRegistry);
    }

    public void processTaggedRequest() {
        taggedCounter.increment();
    }
}
