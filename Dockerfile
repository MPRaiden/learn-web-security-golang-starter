RUN apk add --no-cache ca-certificates && addgroup -S bearly && adduser -S -G bearly bearly
WORKDIR /app
COPY --from=build --chown=bearly:bearly /out/bearly-secure ./bearly-secure
COPY --from=build --chown=bearly:bearly /out/bearly-attacker-lab ./bearly-attacker-lab
COPY --chown=bearly:bearly attacker-lab ./attacker-lab
COPY --chown=bearly:bearly data/fixtures ./data/fixtures
COPY --chown=bearly:bearly web ./web
RUN chown bearly:bearly ./data

USER bearly
EXPOSE 3030 4040
CMD ["./bearly-secure"]

