FROM ghcr.io/graalvm/graalvm-ce:java8 AS build

WORKDIR /code
COPY . .
RUN ./gradlew -b /code/build.gradle nativeBuild

FROM registry.access.redhat.com/ubi8/ubi-minimal:8.4
WORKDIR /work
COPY --from=build /code/build/native/nativeBuild/loguccino /work/
RUN chmod 775 /work
ENTRYPOINT ["./loguccino"]