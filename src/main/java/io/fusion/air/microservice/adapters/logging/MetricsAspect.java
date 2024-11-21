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
package io.fusion.air.microservice.adapters.logging;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.reflect.MethodSignature;

/**
 * ms-springboot-334-vanilla / MetricsAspect
 *
 * @author: Araf Karsh Hamid
 * @version: 0.1
 * @date: 2024-10-08T12:05
 */
@Aspect
@Component
public class MetricsAspect {

    private final MeterRegistry meterRegistry;
    private final MetricsCounterHandler counterHandler;

    /**
     * Metrics Aspect Constructor
     * @param meterRegistry
     * @param counterHandler
     */
    public MetricsAspect(MeterRegistry meterRegistry, MetricsCounterHandler counterHandler) {
        this.meterRegistry = meterRegistry;
        this.counterHandler = counterHandler;
    }

    // @Around("execution(* *(..)) && @within(io.fusion.air.microservice.adapters.logging.MetricsCounter) || @annotation(io.fusion.air.microservice.adapters.logging.MetricsCounter)")
    @Around("@annotation(io.fusion.air.microservice.adapters.logging.MetricsCounter)")
    public Object trackCounter(ProceedingJoinPoint joinPoint) throws Throwable {
        System.out.println("Pass 0");
        MetricModel metricModel = counterHandler.getMetricModel(joinPoint);
        // MetricModel metricModel = getMetricModel(joinPoint);

        if(metricModel == null) {
            System.out.println("Pass 4... Counter Skipped");
            return joinPoint.proceed();
        }
        // Get Counter and Increment the Counter
        counterHandler.getCounter(metricModel.getMetricName(), metricModel.getMetricTags(), meterRegistry).increment();
        // getCounter(metricModel.getMetricName(), metricModel.getMetricTags(), meterRegistry).increment();
        System.out.println("Pass 4... Counter Incremented");
        return joinPoint.proceed(); // Proceed with the method execution
    }

    /**
     * Get the Metric Data from the Function
     * @param joinPoint
     * @return
     */
    private MetricModel getMetricModel(ProceedingJoinPoint joinPoint) {
        System.out.println("< Pass 1");
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        // Check for class-level annotation first
        Class<?> targetClass = signature.getDeclaringType();
        MetricsPath metricClass = targetClass.getAnnotation(MetricsPath.class);
        // Check for method-level annotation
        MetricsCounter metricFunction = signature.getMethod().getAnnotation(MetricsCounter.class);

        String metricName = "METRIC-NAME-NOT-DEFINED";
        String name = "METRICS.PATH.NOT.DEFINED.";
        String endPoint = "METRICS.FUNCTION.NOT.DEFINED";
        String[] tags = null;
        // Extract Class Name and Method Name
        if (metricClass != null) {
            name = metricClass.name();
            System.out.println("< Pass 2.1 - MetricsPath: "+name);
        }
        if (metricFunction != null) {
            if(metricFunction.name() != null && !metricFunction.name().trim().isEmpty()) {
                name = metricFunction.name();
                System.out.println("< Pass 2.2 - Name: "+name);
            }
            endPoint = metricFunction.endpoint().replaceAll("/", ".");  // Use method endpoint
            metricName = name + endPoint;
            tags = metricFunction.tags();
            System.out.println("< Pass 2.3 - Register / Increment");
        } else {
            System.out.println("< Pass 3.1 - Skip");
            // No annotation, proceed without tracking
            return null;
        }
        System.out.println("< Pass 3.1 - Return Model");
        return new MetricModel(name, endPoint, "", tags, metricName);
    }

    private Counter getCounter(String name, String[] tags, MeterRegistry meterRegistry) {
        // Retrieve or create the counter
        Counter counter = null;
        if(tags != null) {
            counter = meterRegistry.find(name).tags(tags).counter();
            if (counter == null) {
                System.out.println("< Pass 3.2 - Adding Metrics: "+name+" <> Tags # = "+tags.length);
                counter = Counter.builder(name)
                        .tags(tags)
                        .register(meterRegistry);
            }
        } else {
            counter = meterRegistry.find(name).counter();
            if (counter == null) {
                System.out.println("< Pass 3.2 - Adding Metrics: "+name+" <> Tags # = []");
                counter = Counter.builder(name)
                        .register(meterRegistry);
            }
        }
        return counter;
    }
}
